// Package mapper builds a model-free map of a target: its languages,
// frameworks, entry points, trust boundaries, and how to build and test it.
// The planner and investigators start from this map instead of rediscovering
// the layout on every run.
package mapper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TMHSDigital/spackle/internal/gitx"
	"github.com/TMHSDigital/spackle/internal/lang"
	"github.com/TMHSDigital/spackle/internal/version"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// Map describes a target on disk.
type Map struct {
	Commit     string       `json:"commit,omitempty"`
	FileCount  int          `json:"file_count"`
	Languages  []LangCount  `json:"languages"`
	Frameworks []string     `json:"frameworks,omitempty"`
	Entry      []EntryPoint `json:"entry_points,omitempty"`
	Boundaries []Boundary   `json:"trust_boundaries,omitempty"`
	InfraFiles []string     `json:"infra_files,omitempty"`
	Tests      Harness      `json:"tests"`
	Skipped    []walk.Skip  `json:"skipped,omitempty"`

	// Files is the listing the map was built from. It is not cached: it
	// holds absolute paths, which belong to one machine.
	Files []walk.File `json:"-"`
}

// LangCount is how many files a language has.
type LangCount struct {
	Lang  string `json:"lang"`
	Files int    `json:"files"`
}

// EntryPoint is a place where execution or outside input enters the program.
type EntryPoint struct {
	Kind   string `json:"kind"` // http-route|main|cli|handler
	File   string `json:"file"`
	Line   int    `json:"line"`
	Detail string `json:"detail"`
}

// Boundary is a line where data crosses a trust boundary.
type Boundary struct {
	Kind string `json:"kind"` // http-input|env|process|database|outbound-http|filesystem|deserialization
	File string `json:"file"`
	Line int    `json:"line"`
}

// Harness says how the target is built and tested, as far as can be told
// without running anything.
type Harness struct {
	Language     string `json:"language,omitempty"` // primary language: go|python|javascript|typescript
	TestCommand  string `json:"test_command,omitempty"`
	BuildCommand string `json:"build_command,omitempty"`
	HasTests     bool   `json:"has_tests"`
}

// LanguageNames returns the language names, most files first.
func (m Map) LanguageNames() []string {
	out := make([]string, 0, len(m.Languages))
	for _, l := range m.Languages {
		out = append(out, l.Lang)
	}
	return out
}

// Options control mapping.
type Options struct {
	// CacheDir, when set, enables the commit-keyed cache.
	CacheDir string
	// Walk holds the configured path exclusions and inclusions. The cache
	// is not used when any are set, because it is keyed by commit alone.
	Walk walk.Options
	// Texts, when set, receives the text of every file the mapper reads,
	// so the seeders that run next do not read those files again.
	Texts *walk.Texts
	// Changed, when set, lists the files (relative to root, with forward
	// slashes) that differ from HEAD: the uncommitted work of a --changed
	// scan. With a cached map of HEAD, only those files are read again and
	// the rest of the map is taken from the cache. Without it, a tree with
	// local changes is mapped in full.
	Changed map[string]bool
}

// Build maps the target at root.
func Build(ctx context.Context, root string, opts Options) (Map, error) {
	listing, err := walk.ListWith(root, opts.Walk)
	if err != nil {
		return Map{}, err
	}
	if len(opts.Walk.Exclude) > 0 || len(opts.Walk.Include) > 0 {
		opts.CacheDir = ""
	}

	// The cache is only valid for an exact commit with no local changes.
	// The state directory, which holds the cache itself, is untracked
	// inside the target by default and is never read by the walk, so it
	// does not count as a change.
	commit, head := "", ""
	if sha, err := gitx.HeadSHA(ctx, root); err == nil {
		if top, terr := gitx.TopLevel(ctx, root); terr == nil && sameDir(top, root) {
			head = sha
			if clean, cerr := gitx.IsCleanExcept(ctx, root, stateDirName); cerr == nil && clean {
				commit = sha
			}
		}
	}
	var prev *cacheFile
	if opts.CacheDir != "" {
		switch {
		case commit != "":
			if c, ok := loadCache(opts.CacheDir, commit); ok {
				c.Map.Files = listing.Files
				return c.Map, nil
			}
		case head != "" && opts.Changed != nil:
			// The work tree differs from HEAD only in the changed files,
			// so the map of HEAD holds the rest.
			if c, ok := loadCache(opts.CacheDir, head); ok {
				prev = &c
			}
		}
	}

	m, fileFrameworks, err := build(ctx, listing, opts, prev)
	if err != nil {
		return Map{}, err
	}
	m.Commit = commit
	if commit != "" && opts.CacheDir != "" {
		// A cache write failure costs time on the next run, nothing else.
		_ = saveCache(opts.CacheDir, commit, m, fileFrameworks)
	}
	return m, nil
}

// build maps a listing. With prev, a cached map of HEAD, a file that is not
// in opts.Changed is not read: what the cache recorded for it is used. The
// result is the same as a full build, because every part of the map is
// either taken from the listing or put together from per-file results in
// the same order. It also returns the frameworks each file it read
// imports, for the cache.
func build(ctx context.Context, listing walk.Result, opts Options, prev *cacheFile) (Map, map[string][]string, error) {
	m := Map{FileCount: len(listing.Files), Files: listing.Files, Skipped: listing.Skipped}
	counts := map[string]int{}
	frameworks := map[string]bool{}
	fileFrameworks := map[string][]string{}
	var manifests []walk.File

	// What the cache knows per file: its entry points and boundaries, the
	// frameworks it imports (present for every file that was read), and
	// why it could not be read.
	var prevEntry map[string][]EntryPoint
	var prevBounds map[string][]Boundary
	prevUnreadable := map[string]walk.Skip{}
	if prev != nil {
		prevEntry, prevBounds = map[string][]EntryPoint{}, map[string][]Boundary{}
		for _, e := range prev.Map.Entry {
			prevEntry[e.File] = append(prevEntry[e.File], e)
		}
		for _, b := range prev.Map.Boundaries {
			prevBounds[b.File] = append(prevBounds[b.File], b)
		}
		for _, sk := range prev.Map.Skipped {
			if strings.HasPrefix(sk.Reason, unreadablePrefix) {
				prevUnreadable[sk.Rel] = sk
			}
		}
	}

	// part is what one file adds to the map. Files are read and scanned
	// on workers, and the parts are put together in listing order, so the
	// map does not depend on which worker finished first.
	type part struct {
		scanned    bool // read and scanned now, or taken from the cache
		skip       *walk.Skip
		entry      []EntryPoint
		boundaries []Boundary
		fws        []string
	}
	parts := make([]part, len(listing.Files))
	var toRead []int
	for i, f := range listing.Files {
		if err := ctx.Err(); err != nil {
			return Map{}, nil, err
		}
		if isCodeLang(f.Lang) {
			counts[f.Lang]++
		}
		if isInfra(f) {
			m.InfraFiles = append(m.InfraFiles, f.Rel)
		}
		if isManifest(f.Rel) {
			manifests = append(manifests, f)
		}
		if !lang.Supported(f.Lang) && f.Lang != "java" && f.Lang != "ruby" && f.Lang != "php" && f.Lang != "csharp" {
			continue
		}
		// Test code is not attack surface: its path says all the map
		// needs, so it is not read.
		if walk.IsTestPath(f.Rel) {
			m.Tests.HasTests = true
			continue
		}
		// A language with no entry, boundary or import patterns adds
		// nothing, so it is not read either.
		if !hasPatterns(f.Lang) {
			continue
		}
		if prev != nil && !opts.Changed[f.Rel] {
			if fws, ok := prev.FileFrameworks[f.Rel]; ok {
				parts[i] = part{scanned: true, entry: prevEntry[f.Rel], boundaries: prevBounds[f.Rel], fws: fws}
				continue
			}
			if sk, ok := prevUnreadable[f.Rel]; ok {
				parts[i].skip = &sk
				continue
			}
			// The cache does not know the file: read it.
		}
		toRead = append(toRead, i)
	}

	workers := min(runtime.GOMAXPROCS(0), maxMapWorkers, len(toRead))
	next := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				f := listing.Files[i]
				text, rerr := readText(opts.Texts, f)
				if rerr != nil {
					parts[i].skip = &walk.Skip{Rel: f.Rel, Reason: unreadablePrefix + rerr.Error()}
					continue
				}
				var pm Map
				parts[i] = part{scanned: true, fws: scanFile(&pm, f, text), entry: pm.Entry, boundaries: pm.Boundaries}
			}
		}()
	}
	for _, i := range toRead {
		if ctx.Err() != nil {
			break
		}
		next <- i
	}
	close(next)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return Map{}, nil, err
	}
	for i, p := range parts {
		switch {
		case p.skip != nil:
			m.Skipped = append(m.Skipped, *p.skip)
		case p.scanned:
			fws := p.fws
			if fws == nil {
				fws = []string{}
			}
			fileFrameworks[listing.Files[i].Rel] = fws
			for _, fw := range fws {
				frameworks[fw] = true
			}
			m.Entry = append(m.Entry, p.entry...)
			m.Boundaries = append(m.Boundaries, p.boundaries...)
		}
	}

	for lang, n := range counts {
		m.Languages = append(m.Languages, LangCount{Lang: lang, Files: n})
	}
	sort.Slice(m.Languages, func(i, j int) bool {
		if m.Languages[i].Files != m.Languages[j].Files {
			return m.Languages[i].Files > m.Languages[j].Files
		}
		return m.Languages[i].Lang < m.Languages[j].Lang
	})

	detectManifests(frameworks, manifests, opts.Texts)
	for fw := range frameworks {
		m.Frameworks = append(m.Frameworks, fw)
	}
	sort.Strings(m.Frameworks)
	sort.Strings(m.InfraFiles)
	// Stable, so rows on the same line keep the order the file gave them
	// and a map put together from the cache equals a full build.
	sort.SliceStable(m.Entry, func(i, j int) bool {
		if m.Entry[i].File != m.Entry[j].File {
			return m.Entry[i].File < m.Entry[j].File
		}
		return m.Entry[i].Line < m.Entry[j].Line
	})
	sort.SliceStable(m.Boundaries, func(i, j int) bool {
		if m.Boundaries[i].File != m.Boundaries[j].File {
			return m.Boundaries[i].File < m.Boundaries[j].File
		}
		return m.Boundaries[i].Line < m.Boundaries[j].Line
	})
	chooseHarness(&m, listing.Files, opts.Texts)
	return m, fileFrameworks, nil
}

// maxMapWorkers bounds how many files the mapper reads and scans at once.
const maxMapWorkers = 8

// hasPatterns reports whether the mapper has any pattern for a language.
func hasPatterns(lang string) bool {
	return entryPatterns[lang] != nil || boundaryPatterns[lang] != nil || importFrameworks[lang] != nil
}

// unreadablePrefix starts the skip reason of a file the mapper could not
// read.
const unreadablePrefix = "unreadable: "

// readText returns the text of f. With a texts it is read from disk once:
// the text is kept there for the mapper's own later steps and for the
// stage that runs next.
func readText(texts *walk.Texts, f walk.File) (string, error) {
	if text, ok := texts.Get(f.Abs); ok {
		return text, nil
	}
	text, err := walk.ReadText(f.Abs)
	if err == nil {
		texts.Put(f.Abs, text)
	}
	return text, err
}

// sameDir reports whether two paths are the same directory. It compares
// file identity, not spelling: on Windows the same directory can be written
// with a short (8.3) name, a different case, or forward slashes.
func sameDir(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}

func isCodeLang(lang string) bool {
	switch lang {
	case "", "yaml", "json", "toml", "html", "xml", "ini", "dotenv", "sql":
		return false
	}
	return true
}

func isInfra(f walk.File) bool {
	switch f.Lang {
	case "dockerfile", "terraform":
		return true
	case "yaml":
		rel := strings.ToLower(f.Rel)
		base := filepath.Base(rel)
		return strings.Contains(rel, ".github/workflows/") || strings.Contains(rel, "k8s") ||
			strings.Contains(rel, "kubernetes") || strings.Contains(rel, "deploy") ||
			strings.Contains(rel, "helm") || strings.Contains(rel, "manifests") ||
			strings.HasPrefix(base, "docker-compose") || strings.HasPrefix(base, "compose.") ||
			base == ".gitlab-ci.yml"
	}
	return false
}

func isManifest(rel string) bool {
	switch strings.ToLower(filepath.Base(rel)) {
	case "go.mod", "package.json", "requirements.txt", "pyproject.toml", "pipfile", "setup.py", "setup.cfg":
		return true
	}
	return false
}

// isTestFile reports whether a path is test code. Test code is not attack
// surface, so it contributes to the harness and not to entry points.
type linePattern struct {
	re     *regexp.Regexp
	kind   string
	detail string // for entry points; may use the first capture group
}

var entryPatterns = map[string][]linePattern{
	"go": {
		{regexp.MustCompile(`^func main\(\)`), "main", "program entry"},
		{regexp.MustCompile(`\b(?:http|mux|router|r|e|g|app|api|srv)\.(?:HandleFunc|Handle)\(\s*"([^"]+)"`), "http-route", "$1"},
		{regexp.MustCompile(`\.(?:GET|POST|PUT|PATCH|DELETE|Any)\(\s*"([^"]+)"`), "http-route", "$1"},
		{regexp.MustCompile(`\.(?:Get|Post|Put|Patch|Delete)\(\s*"(/[^"]*)"`), "http-route", "$1"},
		{regexp.MustCompile(`^func \([^)]*\) ServeHTTP\(`), "handler", "ServeHTTP"},
	},
	"python": {
		{regexp.MustCompile(`^if __name__ == ["']__main__["']`), "main", "script entry"},
		{regexp.MustCompile(`^\s*@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete)\(\s*["']([^"']+)["']`), "http-route", "$1"},
		{regexp.MustCompile(`^\s*def (do_(?:GET|POST|PUT|PATCH|DELETE))\(`), "handler", "$1"},
		{regexp.MustCompile(`^\s*(?:re_)?path\(\s*r?["']([^"']*)["']\s*,`), "http-route", "$1"},
		{regexp.MustCompile(`argparse\.ArgumentParser\(|@click\.command`), "cli", "command line"},
	},
	"javascript": jsEntry,
	"typescript": jsEntry,
}

var jsEntry = []linePattern{
	{regexp.MustCompile(`\b(?:app|router|server|api|fastify)\.(?:get|post|put|patch|delete|all|use)\(\s*["'\x60]([^"'\x60]+)["'\x60]`), "http-route", "$1"},
	{regexp.MustCompile(`\bcreateServer\(`), "handler", "http server"},
	{regexp.MustCompile(`^export (?:default )?(?:async )?function (?:handler|GET|POST|PUT|PATCH|DELETE)\b`), "handler", "route handler"},
}

var boundaryPatterns = map[string][]linePattern{
	"go": {
		{re: regexp.MustCompile(`\br\.(?:URL\.Query\(\)|FormValue\(|PostFormValue\(|Header\.Get\(|Body\b|PathValue\(|Cookie\()|\bc\.(?:Query|Param|PostForm|FormValue|Bind\w*)\(`), kind: "http-input"},
		{re: regexp.MustCompile(`\bos\.(?:Getenv|LookupEnv)\(`), kind: "env"},
		{re: regexp.MustCompile(`\bexec\.Command(?:Context)?\(`), kind: "process"},
		{re: regexp.MustCompile(`\.(?:Query|QueryRow|Exec)(?:Context)?\(`), kind: "database"},
		{re: regexp.MustCompile(`\bhttp\.(?:Get|Post|NewRequest(?:WithContext)?)\(|\.Do\(req`), kind: "outbound-http"},
		{re: regexp.MustCompile(`\bos\.(?:Open|OpenFile|ReadFile|WriteFile|Create|Remove)\(|\bhttp\.ServeFile\(`), kind: "filesystem"},
		{re: regexp.MustCompile(`\b(?:gob\.NewDecoder|xml\.Unmarshal|yaml\.Unmarshal)\(`), kind: "deserialization"},
	},
	"python": {
		{re: regexp.MustCompile(`\brequest\.(?:args|form|json|data|values|files|headers|cookies|GET|POST|body|query_params)\b|\bparse_qs\(|\bself\.(?:path|headers|rfile)\b`), kind: "http-input"},
		{re: regexp.MustCompile(`\bos\.(?:environ|getenv)\b`), kind: "env"},
		{re: regexp.MustCompile(`\bsubprocess\.\w+\(|\bos\.(?:system|popen)\(`), kind: "process"},
		{re: regexp.MustCompile(`\.(?:execute|executemany|executescript)\(`), kind: "database"},
		{re: regexp.MustCompile(`\brequests\.\w+\(|\burlopen\(|\bhttpx\.\w+\(`), kind: "outbound-http"},
		{re: regexp.MustCompile(`\bopen\(|\bsend_file\(|\bos\.remove\(`), kind: "filesystem"},
		{re: regexp.MustCompile(`\b(?:pickle|marshal|yaml)\.loads?\(`), kind: "deserialization"},
	},
	"javascript": jsBoundary,
	"typescript": jsBoundary,
}

var jsBoundary = []linePattern{
	{re: regexp.MustCompile(`\breq(?:uest)?\.(?:query|params|body|headers|cookies)\b|\bsearchParams\.get\(`), kind: "http-input"},
	{re: regexp.MustCompile(`\bprocess\.env\b`), kind: "env"},
	{re: regexp.MustCompile(`\b(?:exec|execSync|spawn|spawnSync|execFile)\(`), kind: "process"},
	{re: regexp.MustCompile(`\.(?:query|execute|raw)\(`), kind: "database"},
	{re: regexp.MustCompile(`\bfetch\(|\baxios(?:\.\w+)?\(|\bhttps?\.(?:get|request)\(`), kind: "outbound-http"},
	{re: regexp.MustCompile(`\bfs\.\w+\(|\.sendFile\(`), kind: "filesystem"},
	{re: regexp.MustCompile(`\bunserialize\(|\byaml\.load\(`), kind: "deserialization"},
}

type importPattern struct {
	re   *regexp.Regexp
	name string
}

// jsImports are the framework imports of JavaScript and TypeScript.
var jsImports = []importPattern{
	{regexp.MustCompile(`(?:require\(|from )["']express["']`), "express"},
	{regexp.MustCompile(`(?:require\(|from )["']fastify["']`), "fastify"},
	{regexp.MustCompile(`(?:require\(|from )["']koa["']`), "koa"},
	{regexp.MustCompile(`from ["']next/`), "next"},
}

// importFrameworks holds, per language, the imports that name a framework.
// Only the patterns of a file's own language are tried on its lines.
var importFrameworks = map[string][]importPattern{
	"go": {
		{regexp.MustCompile(`"github\.com/gin-gonic/gin"`), "gin"},
		{regexp.MustCompile(`"github\.com/labstack/echo`), "echo"},
		{regexp.MustCompile(`"github\.com/go-chi/chi`), "chi"},
		{regexp.MustCompile(`"github\.com/gofiber/fiber`), "fiber"},
		{regexp.MustCompile(`"net/http"`), "net/http"},
	},
	"python": {
		{regexp.MustCompile(`^\s*(?:from|import) flask\b`), "flask"},
		{regexp.MustCompile(`^\s*(?:from|import) django\b`), "django"},
		{regexp.MustCompile(`^\s*(?:from|import) fastapi\b`), "fastapi"},
		{regexp.MustCompile(`^\s*(?:from|import) http\.server\b`), "http.server"},
	},
	"javascript": jsImports,
	"typescript": jsImports,
}

// maxPerFile bounds how many entries one file can add, so a generated file
// cannot swamp the map.
const maxPerFile = 60

func scanFile(m *Map, f walk.File, text string) []string {
	entries := entryPatterns[f.Lang]
	bounds := boundaryPatterns[f.Lang]
	imports := importFrameworks[f.Lang]
	added := 0
	found := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		if len(line) > 2000 {
			continue // minified or generated
		}
		for _, fw := range imports {
			if fw.re.MatchString(line) {
				found[fw.name] = true
			}
		}
		if added >= maxPerFile {
			continue
		}
		for _, p := range entries {
			if sub := p.re.FindStringSubmatch(line); sub != nil {
				detail := p.detail
				if len(sub) > 1 {
					detail = strings.ReplaceAll(detail, "$1", sub[1])
				}
				m.Entry = append(m.Entry, EntryPoint{Kind: p.kind, File: f.Rel, Line: i + 1, Detail: detail})
				added++
				break
			}
		}
		for _, p := range bounds {
			if p.re.MatchString(line) {
				// No break: one line can cross several boundaries, for
				// example request input passed straight to a subprocess.
				m.Boundaries = append(m.Boundaries, Boundary{Kind: p.kind, File: f.Rel, Line: i + 1})
				added++
			}
		}
	}
	fws := make([]string, 0, len(found))
	for fw := range found {
		fws = append(fws, fw)
	}
	sort.Strings(fws)
	return fws
}

func detectManifests(frameworks map[string]bool, manifests []walk.File, texts *walk.Texts) {
	deps := map[string]string{
		"flask": "flask", "django": "django", "fastapi": "fastapi", "sqlalchemy": "sqlalchemy",
		`"express"`: "express", `"next"`: "next", `"react"`: "react", `"fastify"`: "fastify", `"koa"`: "koa",
		"gin-gonic/gin": "gin", "labstack/echo": "echo", "go-chi/chi": "chi", "gofiber/fiber": "fiber",
	}
	for _, f := range manifests {
		text, err := readText(texts, f)
		if err != nil {
			continue
		}
		lower := strings.ToLower(text)
		for needle, name := range deps {
			if strings.Contains(lower, needle) {
				frameworks[name] = true
			}
		}
	}
}

func chooseHarness(m *Map, files []walk.File, texts *walk.Texts) {
	has := func(rel string) (walk.File, bool) {
		for _, f := range files {
			if strings.EqualFold(f.Rel, rel) {
				return f, true
			}
		}
		return walk.File{}, false
	}
	primary := ""
	for _, l := range m.Languages {
		if lang.Supported(l.Lang) {
			primary = l.Lang
			break
		}
	}
	m.Tests.Language = primary
	switch primary {
	case "go":
		if _, ok := has("go.mod"); ok {
			m.Tests.BuildCommand = "go build ./..."
			m.Tests.TestCommand = "go test ./..."
		}
	case "python":
		usesPytest := false
		for _, name := range []string{"requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.cfg", "tox.ini", "pytest.ini"} {
			if f, ok := has(name); ok {
				if text, err := readText(texts, f); err == nil && strings.Contains(strings.ToLower(text), "pytest") {
					usesPytest = true
				}
			}
		}
		switch {
		case usesPytest:
			m.Tests.TestCommand = "python -m pytest -q"
		case m.Tests.HasTests:
			m.Tests.TestCommand = "python -m unittest discover"
		}
	case "javascript", "typescript":
		if f, ok := has("package.json"); ok {
			if text, err := readText(texts, f); err == nil {
				var pkg struct {
					Scripts map[string]string `json:"scripts"`
				}
				if json.Unmarshal([]byte(text), &pkg) == nil {
					if t := pkg.Scripts["test"]; t != "" && !strings.Contains(t, "no test specified") {
						m.Tests.TestCommand = "npm test"
					}
					if pkg.Scripts["build"] != "" {
						m.Tests.BuildCommand = "npm run build"
					}
				}
			}
		}
	}
}

// stateDirName is the default state directory. The walk prunes a directory
// of this name wherever it is, so nothing in it is part of the map.
const stateDirName = ".spackle"

// cacheVersion changes whenever the Map shape or the detection rules
// change, so an old cache entry is never trusted.
const cacheVersion = 3

type cacheFile struct {
	Version int `json:"version"`
	// Spackle is the build that wrote the entry. Another build may list
	// or read the target differently (skip rules, entry patterns), so its
	// entry is not trusted even when cacheVersion was not bumped.
	Spackle string `json:"spackle"`
	Map     Map    `json:"map"`
	// FileFrameworks holds, for every file the mapper read, the frameworks
	// it imports (often none). A --changed scan uses it to put the map of
	// a tree with local changes together without reading every file.
	FileFrameworks map[string][]string `json:"file_frameworks"`
}

// builtBy names this build of Spackle for the cache.
func builtBy() string { return version.Version + "+" + version.Commit }

func cachePath(dir, commit string) string {
	return filepath.Join(dir, fmt.Sprintf("map-%s.json", commit))
}

func loadCache(dir, commit string) (cacheFile, bool) {
	b, err := os.ReadFile(cachePath(dir, commit)) //nolint:gosec // path is built from the state directory and a commit hash
	if err != nil {
		return cacheFile{}, false
	}
	var c cacheFile
	if json.Unmarshal(b, &c) != nil || c.Version != cacheVersion || c.Spackle != builtBy() || c.Map.Commit != commit || c.FileFrameworks == nil {
		return cacheFile{}, false
	}
	return c, true
}

func saveCache(dir, commit string, m Map, fileFrameworks map[string][]string) error {
	if !isHex(commit) {
		return errors.New("commit is not a hash")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cacheFile{Version: cacheVersion, Spackle: builtBy(), Map: m, FileFrameworks: fileFrameworks}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(cachePath(dir, commit), append(b, '\n'), 0o600); err != nil {
		return err
	}
	pruneCache(dir, commit)
	return nil
}

// maxCacheEntries is how many map cache files are kept. One is written per
// scanned commit; without a limit they would pile up in the state directory.
const maxCacheEntries = 20

// pruneCache deletes the oldest map cache files beyond maxCacheEntries,
// never the one for keep. It is best effort: a file it cannot delete stays.
func pruneCache(dir, keep string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type entry struct {
		name string
		mod  time.Time
	}
	var maps []entry
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "map-") || !strings.HasSuffix(name, ".json") || name == filepath.Base(cachePath(dir, keep)) {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		maps = append(maps, entry{name, info.ModTime()})
	}
	// Newest first; the entry for keep is not in the list and takes one slot.
	sort.Slice(maps, func(i, j int) bool {
		if !maps[i].mod.Equal(maps[j].mod) {
			return maps[i].mod.After(maps[j].mod)
		}
		return maps[i].name > maps[j].name
	})
	for i := maxCacheEntries - 1; i < len(maps); i++ {
		_ = os.Remove(filepath.Join(dir, maps[i].name))
	}
}

func isHex(s string) bool {
	if len(s) < 7 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
