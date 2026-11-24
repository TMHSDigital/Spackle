package seed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/redact"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// scannerTimeout bounds one scanner run so a hung tool cannot hang a scan.
const scannerTimeout = 10 * time.Minute

// Noter is implemented by seeders that have something to say about their
// last Run beyond the leads, such as how many scanner results were dropped
// because they could not be classified. Callers may type-assert a Seeder to
// Noter after Run.
type Noter interface {
	Note() string
}

// parseStats counts scanner results that did not become leads. Dropping is
// reported, never silent, so an operator can tell a clean scan from one
// whose results were not understood.
type parseStats struct {
	unclassified int // no class in finding.DefaultVector fits
	outside      int // path missing or not inside the target
}

func (s parseStats) note() string {
	var parts []string
	if s.unclassified > 0 {
		parts = append(parts, fmt.Sprintf("%d result(s) skipped because no Spackle class fits them", s.unclassified))
	}
	if s.outside > 0 {
		parts = append(parts, fmt.Sprintf("%d result(s) skipped because their path is not a file inside the target", s.outside))
	}
	return strings.Join(parts, "; ")
}

// external adapts one installed scanner. All scanner output is untrusted
// input: paths are validated against the target root and every text field
// is redacted before it enters a lead.
type external struct {
	name string
	bin  string
	site string // the project's canonical domain, for the install hint
	// args builds the argument vector; ok is false when the target has
	// nothing this scanner looks at.
	args func(root string, files []walk.File) (argv []string, ok bool)
	// leads converts the scanner's JSON to leads.
	leads func(data []byte, root string, st *parseStats) ([]Lead, error)
	// quietExit lists exit codes that mean "nothing to scan" for this tool
	// when it printed no JSON.
	quietExit []int
	// network says whether the tool reaches out when it runs. Every adapter
	// states it; one that does not counts as using the network, so a new
	// adapter is kept out of offline mode until someone decides otherwise.
	network netUse

	mu   sync.Mutex
	note string
}

// netUse says whether a scanner uses the network when it runs.
type netUse int

const (
	netUnstated  netUse = iota // not declared: treated as downloads
	netLocal                   // works on local files only
	netDownloads               // fetches rules or a vulnerability database
)

// NetworkUser is implemented by a seeder that may use the network when it
// runs. Offline mode promises that nothing leaves the machine, so it does
// not run a seeder that reports true.
type NetworkUser interface {
	UsesNetwork() bool
}

// UsesNetwork implements NetworkUser.
func (e *external) UsesNetwork() bool { return e.network != netLocal }

// External returns the adapters for scanners the operator may have installed.
func External() []Seeder {
	return []Seeder{
		&external{
			name: "semgrep", bin: "semgrep", network: netDownloads, site: "semgrep.dev", leads: semgrepLeads,
			args: func(root string, _ []walk.File) ([]string, bool) {
				return []string{"scan", "--json", "--quiet", "--config", "auto", "--metrics", "off", root}, true
			},
		},
		&external{
			name: "gitleaks", bin: "gitleaks", network: netLocal, site: "gitleaks.io", leads: gitleaksLeads,
			args: func(root string, _ []walk.File) ([]string, bool) {
				return []string{"dir", "--report-format", "json", "--report-path", "-", "--redact", "--no-banner", "--exit-code", "0", root}, true
			},
		},
		&external{
			name: "osv-scanner", bin: "osv-scanner", network: netDownloads, site: "google.github.io/osv-scanner", leads: osvLeads,
			// 128 is osv-scanner's "no package sources found".
			quietExit: []int{128},
			args: func(root string, _ []walk.File) ([]string, bool) {
				return []string{"scan", "source", "--format", "json", "-r", root}, true
			},
		},
		&external{
			name: "trivy", bin: "trivy", network: netDownloads, site: "trivy.dev", leads: trivyLeads,
			args: func(root string, _ []walk.File) ([]string, bool) {
				return []string{"fs", "--format", "json", "--quiet", "--scanners", "vuln,misconfig", root}, true
			},
		},
		&external{
			name: "hadolint", bin: "hadolint", network: netLocal, site: "hadolint.github.io/hadolint", leads: hadolintLeads,
			args: func(_ string, files []walk.File) ([]string, bool) {
				argv := []string{"--format", "json"}
				for _, f := range files {
					if f.Lang == "dockerfile" {
						argv = append(argv, filepath.FromSlash(f.Rel))
					}
				}
				return argv, len(argv) > 2
			},
		},
	}
}

func (e *external) Name() string { return e.name }

// Note returns what the last Run dropped, or "".
func (e *external) Note() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.note
}

func (e *external) Available() (bool, string) {
	if _, err := exec.LookPath(e.bin); err != nil {
		return false, fmt.Sprintf("%s is not installed or not on PATH. Follow the official install guide at %s, then run the scan again. Spackle works without it using the built-in rules.", e.bin, e.site)
	}
	return true, ""
}

func (e *external) Run(ctx context.Context, root string, files []walk.File) ([]Lead, error) {
	e.setNote("")
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("%s was not run: the target path %s cannot be made absolute: %w; pass an existing directory", e.name, root, err)
	}
	argv, ok := e.args(absRoot, files)
	if !ok {
		return nil, nil
	}
	binPath, err := exec.LookPath(e.bin)
	if err != nil {
		return nil, fmt.Errorf("%s was not run: it is not on PATH: %w; install it from %s or remove it from the seeder list", e.name, err, e.site)
	}
	ctx, cancel := context.WithTimeout(ctx, scannerTimeout)
	defer cancel()

	// An argument vector, never a shell: the target path and file names are
	// passed as single arguments and cannot be reinterpreted.
	cmd := exec.CommandContext(ctx, binPath, argv...) //nolint:gosec // fixed scanner binary from PATH with a fixed argument vector; only the target path and listed file names vary
	cmd.Dir = absRoot
	// A scanner's report is held in memory and decoded in one piece, so it
	// is bounded: past the limit the rest is dropped and the run is
	// reported as failed instead of exhausting memory.
	stdout := &limitedBuffer{limit: maxScannerOutput}
	stderr := &limitedBuffer{limit: 1 << 20}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	runErr := cmd.Run()

	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s did not finish within %s or the scan was cancelled: %w; rerun, or scan a smaller target", e.name, scannerTimeout, ctx.Err())
	}
	if stdout.truncated {
		return nil, fmt.Errorf("%s produced a report larger than %d MiB, which is not read; exclude generated or vendored paths with [scan] exclude, or run %s by hand", e.name, maxScannerOutput>>20, e.bin)
	}
	if len(bytes.TrimSpace(stdout.Bytes())) == 0 {
		var exitErr *exec.ExitError
		if runErr == nil || (errors.As(runErr, &exitErr) && slices.Contains(e.quietExit, exitErr.ExitCode())) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s failed without producing a report: %w; its error output was: %s; run %s by hand on the target to see the full message", e.name, runErr, scrub(stderr.String(), 300), e.bin)
	}
	// Scanners exit non-zero when they find something, so the exit status
	// is only consulted when the report cannot be read.
	var st parseStats
	leads, err := e.leads(stdout.Bytes(), absRoot, &st)
	if err != nil {
		if runErr != nil {
			return nil, fmt.Errorf("%s failed (%w) and its output is not a readable report: %w; its error output was: %s; run %s by hand on the target to see the full message", e.name, runErr, err, scrub(stderr.String(), 300), e.bin)
		}
		return nil, err
	}
	e.setNote(st.note())
	return leads, nil
}

func (e *external) setNote(n string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.note = n
}

// scrub prepares scanner text for a lead or an error: redacted, collapsed
// to one line, and bounded.
func scrub(s string, limit int) string {
	out, _ := redact.Apply(strings.Join(strings.Fields(s), " "))
	return truncate(out, limit)
}

// scannerPath converts a path printed by a scanner to a forward-slash path
// relative to root. It reports false for anything that is not an existing
// file inside the target, because scanner output is untrusted and a lead
// must never point Spackle at a file outside the target.
func scannerPath(root, p string) (string, bool) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", false
	}
	native := filepath.FromSlash(strings.ReplaceAll(p, `\`, "/"))
	if filepath.IsAbs(native) {
		rel, ok := relToRoot(root, native)
		if !ok {
			return "", false
		}
		native = rel
	}
	rel := path.Clean(filepath.ToSlash(native))
	if rel == "." {
		return "", false
	}
	if _, err := walk.Resolve(root, rel); err != nil {
		return "", false
	}
	return rel, true
}

// relToRoot makes an absolute scanner path relative to root. Scanners print
// either the path they were given or its symlink-free form, so both
// spellings of the root are tried.
func relToRoot(root, abs string) (string, bool) {
	bases := []string{root}
	if a, err := filepath.Abs(root); err == nil {
		bases = append(bases, a)
		if r, err := filepath.EvalSymlinks(a); err == nil {
			bases = append(bases, r)
		}
	}
	for _, base := range bases {
		if !filepath.IsAbs(base) || !walk.Inside(base, abs) {
			continue
		}
		if rel, err := filepath.Rel(base, abs); err == nil {
			return rel, true
		}
	}
	return "", false
}

var cweNumber = regexp.MustCompile(`(?i)CWE-(\d+)`)

// normalizeCWE returns "CWE-<n>" for any spelling that contains one, such
// as semgrep's "CWE-89: Improper Neutralization ...", or "".
func normalizeCWE(s string) string {
	m := cweNumber.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return "CWE-" + m[1]
}

var cweClasses = map[string]string{
	"89": "sql-injection", "564": "sql-injection", "943": "sql-injection",
	"77": "command-injection", "78": "command-injection", "88": "command-injection",
	// Generic and less common injection CWEs fall back to code-injection:
	// the weakness is still "input interpreted as code or query".
	"74": "code-injection", "75": "code-injection", "90": "code-injection", "91": "code-injection",
	"94": "code-injection", "95": "code-injection", "96": "code-injection", "643": "code-injection",
	"917":  "code-injection",
	"502":  "unsafe-deserialization",
	"1336": "template-injection",
	"22":   "path-traversal", "23": "path-traversal", "36": "path-traversal", "73": "path-traversal",
	"918": "ssrf",
	"79":  "xss", "80": "xss", "116": "xss",
	"601": "open-redirect",
	"259": "hardcoded-secret", "321": "hardcoded-secret", "798": "hardcoded-secret",
	"326": "weak-crypto", "327": "weak-crypto",
	"328": "weak-hash", "916": "weak-hash",
	"330": "insecure-random", "331": "insecure-random", "338": "insecure-random",
	"295": "tls-verification", "297": "tls-verification",
	"345": "jwt-verification", "347": "jwt-verification",
	"287": "auth-bypass", "306": "auth-bypass",
	"284": "broken-access-control", "285": "broken-access-control", "639": "broken-access-control",
	"862": "broken-access-control", "863": "broken-access-control",
	"346": "cors-misconfiguration", "942": "cors-misconfiguration",
	"215": "debug-enabled", "489": "debug-enabled",
	"200": "information-disclosure", "209": "information-disclosure", "532": "information-disclosure",
	"1021": "missing-security-header",
	"614":  "insecure-cookie", "1004": "insecure-cookie",
	"362": "race-condition", "367": "race-condition",
	"937": "vulnerable-dependency", "1035": "vulnerable-dependency", "1395": "vulnerable-dependency",
	"250": "container-privilege", "269": "container-privilege",
	"494": "supply-chain", "829": "supply-chain", "1357": "supply-chain",
	"311": "unencrypted-storage", "312": "unencrypted-storage",
	"400": "denial-of-service", "770": "denial-of-service", "1333": "denial-of-service",
	"611": "xxe", "776": "xxe",
	"1321": "prototype-pollution",
	"915":  "mass-assignment",
	"548":  "directory-listing",
}

// classForCWE maps a CWE to the closest class that has a default vector.
// It returns "" for a CWE it does not know: an unclassified result is
// skipped and counted rather than filed under a class that would give it a
// misleading score.
func classForCWE(cwe string) string {
	return cweClasses[strings.TrimPrefix(normalizeCWE(cwe), "CWE-")]
}

// severityWord maps the severity vocabularies of the scanners to Spackle's.
func severityWord(s, fallback string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "critical"
	case "HIGH", "ERROR":
		return "high"
	case "MEDIUM", "MODERATE", "WARNING":
		return "medium"
	case "LOW", "INFO", "STYLE", "UNKNOWN":
		return "low"
	}
	return fallback
}

// stringList decodes a JSON value that tools emit either as one string or
// as a list of strings.
type stringList []string

func (l *stringList) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*l = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		// An unexpected shape in optional metadata is not worth failing
		// the whole report for.
		*l = nil
		return nil //nolint:nilerr // tolerated on purpose, see above
	}
	*l = many
	return nil
}

func badReport(tool string, err error) error {
	return fmt.Errorf("%s output is not the JSON report Spackle expects: %w; check that the installed %s is a current release", tool, err, tool)
}

// ---- semgrep ----

type semgrepReport struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
		// extra.lines is deliberately not decoded: it is target source
		// that may hold a secret.
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Metadata struct {
				CWE   stringList `json:"cwe"`
				OWASP stringList `json:"owasp"`
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

// parseSemgrep converts `semgrep scan --json` output to leads. The class
// comes from the first CWE in the rule's metadata that classForCWE knows;
// results with no such CWE are skipped.
func parseSemgrep(data []byte, root string) ([]Lead, error) {
	return semgrepLeads(data, root, &parseStats{})
}

func semgrepLeads(data []byte, root string, st *parseStats) ([]Lead, error) {
	var rep semgrepReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, badReport("semgrep", err)
	}
	var leads []Lead
	for _, r := range rep.Results {
		class, cwes := "", []string(nil)
		for _, raw := range r.Extra.Metadata.CWE {
			c := normalizeCWE(raw)
			if c == "" {
				continue
			}
			cwes = append(cwes, c)
			if class == "" {
				class = classForCWE(c)
			}
		}
		if class == "" {
			st.unclassified++
			continue
		}
		rel, ok := scannerPath(root, r.Path)
		if !ok {
			st.outside++
			continue
		}
		l := Lead{
			RuleID:   scrub(r.CheckID, 200),
			Title:    ruleTitle(r.CheckID),
			Class:    class,
			Surface:  finding.SurfaceOf(class),
			CWE:      cwes,
			Severity: severityWord(r.Extra.Severity, "medium"),
			File:     rel,
			Line:     r.Start.Line,
			Detail:   scrub(r.Extra.Message, 500),
			Fix:      "Review the flagged code against the guidance of this semgrep rule and apply the fix it recommends.",
		}
		for _, o := range r.Extra.Metadata.OWASP {
			l.OWASP = append(l.OWASP, scrub(o, 100))
		}
		if r.End.Line > r.Start.Line {
			l.EndLine = r.End.Line
		}
		leads = append(leads, l)
	}
	return leads, nil
}

// ruleTitle turns a dotted rule id into a short title using its last
// segment, which is the part a rule author chose to be descriptive.
func ruleTitle(id string) string {
	last := id[strings.LastIndex(id, ".")+1:]
	t := strings.TrimSpace(strings.NewReplacer("-", " ", "_", " ").Replace(last))
	if t == "" {
		t = "semgrep finding"
	}
	return scrub(t, 100)
}

// ---- gitleaks ----

// gitleaksFinding has no Secret and no Match field on purpose: what is not
// decoded cannot leak into a lead.
type gitleaksFinding struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
}

// parseGitleaks converts a gitleaks JSON report to leads. Every result is
// a hardcoded secret, so there is no fallback class.
func parseGitleaks(data []byte, root string) ([]Lead, error) {
	return gitleaksLeads(data, root, &parseStats{})
}

func gitleaksLeads(data []byte, root string, st *parseStats) ([]Lead, error) {
	var found []gitleaksFinding
	if err := json.Unmarshal(data, &found); err != nil {
		return nil, badReport("gitleaks", err)
	}
	var leads []Lead
	for _, f := range found {
		rel, ok := scannerPath(root, f.File)
		if !ok {
			st.outside++
			continue
		}
		rule := scrub(f.RuleID, 100)
		detail := scrub(f.Description, 300)
		if detail == "" {
			detail = "gitleaks rule " + rule + " matched a credential"
		}
		l := Lead{
			RuleID:   rule,
			Title:    "Hardcoded secret (" + rule + ")",
			Class:    "hardcoded-secret",
			Surface:  finding.SurfaceCode,
			CWE:      []string{"CWE-798"},
			OWASP:    []string{owaspAuth},
			Severity: "high",
			File:     rel,
			Line:     f.StartLine,
			Detail:   strings.TrimSuffix(detail, ".") + ". A credential stored in the repository is readable by everyone with access to the code and its history.",
			Fix:      "Revoke and rotate this credential, then load the new one from the environment or a secret manager. Removing the line is not enough because the value stays in version control history.",
		}
		if f.EndLine > f.StartLine {
			l.EndLine = f.EndLine
		}
		leads = append(leads, l)
	}
	return leads, nil
}

// ---- osv-scanner ----

type osvReport struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID       string `json:"id"`
				Summary  string `json:"summary"`
				Affected []struct {
					Package struct {
						Name string `json:"name"`
					} `json:"package"`
					Ranges []struct {
						Events []struct {
							Fixed string `json:"fixed"`
						} `json:"events"`
					} `json:"ranges"`
				} `json:"affected"`
			} `json:"vulnerabilities"`
			Groups []struct {
				IDs         []string `json:"ids"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

// parseOSV converts `osv-scanner --format json` output to leads. Every
// result is a known-vulnerable dependency, so there is no fallback class.
func parseOSV(data []byte, root string) ([]Lead, error) {
	return osvLeads(data, root, &parseStats{})
}

func osvLeads(data []byte, root string, st *parseStats) ([]Lead, error) {
	var rep osvReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, badReport("osv-scanner", err)
	}
	var leads []Lead
	for _, res := range rep.Results {
		rel, ok := scannerPath(root, res.Source.Path)
		for _, p := range res.Packages {
			if !ok {
				st.outside += len(p.Vulnerabilities)
				continue
			}
			name, version := scrub(p.Package.Name, 100), scrub(p.Package.Version, 50)
			scores := map[string]string{}
			for _, g := range p.Groups {
				for _, id := range g.IDs {
					scores[id] = g.MaxSeverity
				}
			}
			for _, v := range p.Vulnerabilities {
				id := scrub(v.ID, 60)
				fixed := ""
				for _, a := range v.Affected {
					if a.Package.Name != p.Package.Name {
						continue
					}
					for _, r := range a.Ranges {
						for _, ev := range r.Events {
							if fixed == "" && ev.Fixed != "" {
								fixed = scrub(ev.Fixed, 50)
							}
						}
					}
				}
				summary := scrub(v.Summary, 300)
				if summary == "" {
					summary = "No summary was published"
				}
				fix := fmt.Sprintf("Upgrade %s to a release that is not affected by %s and rebuild the lockfile.", name, id)
				if fixed != "" {
					fix = fmt.Sprintf("Upgrade %s to %s or later, which fixes %s, and rebuild the lockfile.", name, fixed, id)
				}
				leads = append(leads, Lead{
					// The package is part of the rule id so the same
					// advisory on two packages of one lockfile stays two leads.
					RuleID:   id + ":" + name,
					Title:    fmt.Sprintf("%s %s is affected by %s", name, version, id),
					Class:    "vulnerable-dependency",
					Surface:  finding.SurfaceCode,
					CWE:      []string{"CWE-1395"},
					OWASP:    []string{"A06:2021 Vulnerable and Outdated Components"},
					Severity: cvssWord(scores[v.ID]),
					File:     rel,
					Detail:   fmt.Sprintf("%s %s: %s.", name, version, strings.TrimSuffix(summary, ".")),
					Fix:      fix,
				})
			}
		}
	}
	return leads, nil
}

// cvssWord turns a CVSS base score into a severity word. A missing score
// becomes medium: the advisory is real, its impact is just not rated.
func cvssWord(score string) string {
	f, err := strconv.ParseFloat(strings.TrimSpace(score), 64)
	switch {
	case err != nil || f <= 0:
		return "medium"
	case f >= 9:
		return "critical"
	case f >= 7:
		return "high"
	case f >= 4:
		return "medium"
	}
	return "low"
}

// ---- trivy ----

type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Title            string `json:"Title"`
			Severity         string `json:"Severity"`
		} `json:"Vulnerabilities"`
		Misconfigurations []struct {
			ID            string `json:"ID"`
			Title         string `json:"Title"`
			Description   string `json:"Description"`
			Message       string `json:"Message"`
			Resolution    string `json:"Resolution"`
			Severity      string `json:"Severity"`
			CauseMetadata struct {
				StartLine int `json:"StartLine"`
				EndLine   int `json:"EndLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
	} `json:"Results"`
}

// parseTrivy converts `trivy fs --format json` output to leads.
// Vulnerabilities are always vulnerable-dependency. Misconfigurations have
// no CWE, so trivyMisconfigClass picks the class from the file type and
// the check's title; checks it cannot place are skipped.
func parseTrivy(data []byte, root string) ([]Lead, error) {
	return trivyLeads(data, root, &parseStats{})
}

func trivyLeads(data []byte, root string, st *parseStats) ([]Lead, error) {
	var rep trivyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, badReport("trivy", err)
	}
	var leads []Lead
	for _, res := range rep.Results {
		rel, ok := scannerPath(root, res.Target)
		if !ok {
			st.outside += len(res.Vulnerabilities) + len(res.Misconfigurations)
			continue
		}
		for _, v := range res.Vulnerabilities {
			id, name, version := scrub(v.VulnerabilityID, 60), scrub(v.PkgName, 100), scrub(v.InstalledVersion, 50)
			title := scrub(v.Title, 300)
			if title == "" {
				title = "No summary was published"
			}
			fix := fmt.Sprintf("Upgrade %s to a release that is not affected by %s and rebuild the lockfile.", name, id)
			if fv := scrub(v.FixedVersion, 80); fv != "" {
				fix = fmt.Sprintf("Upgrade %s to %s or later, which fixes %s, and rebuild the lockfile.", name, fv, id)
			}
			leads = append(leads, Lead{
				RuleID:   id + ":" + name,
				Title:    fmt.Sprintf("%s %s is affected by %s", name, version, id),
				Class:    "vulnerable-dependency",
				Surface:  finding.SurfaceCode,
				CWE:      []string{"CWE-1395"},
				OWASP:    []string{"A06:2021 Vulnerable and Outdated Components"},
				Severity: severityWord(v.Severity, "medium"),
				File:     rel,
				Detail:   fmt.Sprintf("%s %s: %s.", name, version, strings.TrimSuffix(title, ".")),
				Fix:      fix,
			})
		}
		for _, m := range res.Misconfigurations {
			class, cwe := trivyMisconfigClass(res.Type, m.Title+" "+m.Description)
			if class == "" {
				st.unclassified++
				continue
			}
			detail := scrub(m.Message, 400)
			if detail == "" {
				detail = scrub(m.Description, 400)
			}
			fix := scrub(m.Resolution, 300)
			if fix == "" {
				fix = "Apply the remediation described for this check in the Trivy documentation."
			}
			l := Lead{
				RuleID:   scrub(m.ID, 60),
				Title:    strings.TrimSuffix(scrub(m.Title, 120), "."),
				Class:    class,
				Surface:  finding.SurfaceInfra,
				CWE:      []string{cwe},
				OWASP:    []string{owaspMisconfig},
				Severity: severityWord(m.Severity, "low"),
				File:     rel,
				Line:     m.CauseMetadata.StartLine,
				Detail:   detail,
				Fix:      fix,
			}
			if m.CauseMetadata.EndLine > m.CauseMetadata.StartLine {
				l.EndLine = m.CauseMetadata.EndLine
			}
			leads = append(leads, l)
		}
	}
	return leads, nil
}

var (
	trivyPrivRe    = regexp.MustCompile(`(?i)privileged|host ?(?:network|pid|ipc|path)|capabilit|docker\.sock`)
	trivyLatestRe  = regexp.MustCompile(`(?i):latest|latest tag|image tag`)
	trivyPublicRe  = regexp.MustCompile(`(?i)public(?:ly)?[ -](?:read|write|access|acl)|public access block|bucket.*public|public.*bucket`)
	trivyEncryptRe = regexp.MustCompile(`(?i)encrypt`)
	trivyNetworkRe = regexp.MustCompile(`(?i)ingress|egress|security group|0\.0\.0\.0|public ip|publicly accessible|open to the internet|firewall`)
)

// trivyMisconfigClass places a misconfiguration check. Container file
// types default to container-hardening because every Trivy check on a
// Dockerfile or manifest is a hardening check; cloud configuration has no
// such safe default, so unrecognized checks there return "".
func trivyMisconfigClass(fileType, text string) (class, cwe string) {
	switch strings.ToLower(fileType) {
	case "dockerfile", "kubernetes", "helm":
		switch {
		case trivyPrivRe.MatchString(text):
			return "container-privilege", "CWE-250"
		case trivyLatestRe.MatchString(text):
			return "supply-chain", "CWE-1357"
		}
		return "container-hardening", "CWE-250"
	}
	switch {
	case trivyPublicRe.MatchString(text):
		return "public-storage", "CWE-732"
	case trivyEncryptRe.MatchString(text):
		return "unencrypted-storage", "CWE-311"
	case trivyNetworkRe.MatchString(text):
		return "network-exposure", "CWE-284"
	}
	return "", ""
}

// ---- hadolint ----

type hadolintFinding struct {
	Code    string `json:"code"`
	File    string `json:"file"`
	Level   string `json:"level"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// hadolintClasses lists the hadolint rules with a security meaning. The
// rest are style and build hygiene (and shellcheck codes), which are not
// leads; they are skipped and counted.
var hadolintClasses = map[string][2]string{
	"DL3002": {"container-hardening", "CWE-250"}, // last USER should not be root
	"DL3004": {"container-hardening", "CWE-250"}, // do not use sudo
	"DL3006": {"supply-chain", "CWE-1357"},       // always tag the image
	"DL3007": {"supply-chain", "CWE-1357"},       // do not use latest
	"DL3008": {"supply-chain", "CWE-1357"},       // pin versions in apt-get install
	"DL3013": {"supply-chain", "CWE-1357"},       // pin versions in pip install
	"DL3016": {"supply-chain", "CWE-1357"},       // pin versions in npm install
	"DL3018": {"supply-chain", "CWE-1357"},       // pin versions in apk add
	"DL3028": {"supply-chain", "CWE-1357"},       // pin versions in gem install
}

// parseHadolint converts `hadolint --format json` output to leads using
// hadolintClasses; rules outside that table are skipped.
func parseHadolint(data []byte, root string) ([]Lead, error) {
	return hadolintLeads(data, root, &parseStats{})
}

func hadolintLeads(data []byte, root string, st *parseStats) ([]Lead, error) {
	var found []hadolintFinding
	if err := json.Unmarshal(data, &found); err != nil {
		return nil, badReport("hadolint", err)
	}
	var leads []Lead
	for _, f := range found {
		cc, ok := hadolintClasses[strings.ToUpper(strings.TrimSpace(f.Code))]
		if !ok {
			st.unclassified++
			continue
		}
		rel, ok := scannerPath(root, f.File)
		if !ok {
			st.outside++
			continue
		}
		msg := strings.TrimSuffix(scrub(f.Message, 300), ".")
		sev := "low"
		if strings.EqualFold(f.Level, "error") {
			sev = "medium"
		}
		leads = append(leads, Lead{
			RuleID:   strings.ToUpper(strings.TrimSpace(f.Code)),
			Title:    truncate(msg, 100),
			Class:    cc[0],
			Surface:  finding.SurfaceInfra,
			CWE:      []string{cc[1]},
			Severity: sev,
			File:     rel,
			Line:     f.Line,
			Detail:   "hadolint: " + msg + ".",
			Fix:      "Change the instruction as the message describes; the hadolint wiki page for this rule shows a corrected example.",
		})
	}
	return leads, nil
}

// maxScannerOutput bounds the report one external scanner may write.
const maxScannerOutput = 256 << 20

// limitedBuffer is a bytes.Buffer that stops growing at limit and records
// that it had to drop output. Writes always succeed, so the scanner is not
// killed by a closed pipe and can finish and exit normally.
type limitedBuffer struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.Len(); room < len(p) {
		b.truncated = true
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}
