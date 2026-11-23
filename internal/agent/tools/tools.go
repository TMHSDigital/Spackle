// Package tools is the allowlisted, read-only tool set an investigator model
// uses to look at a target.
//
// The model reads the target through these tools and nothing else. There is
// no shell, no write and no network tool here, so text planted in the target
// has nothing to drive. Every path a model supplies goes through
// walk.Resolve, every result is redacted and then sealed in an envelope, and
// limits (output size, result counts, line windows) are constants in Go that
// no argument can raise past their caps.
package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/TMHSDigital/spackle/internal/envelope"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/redact"
	"github.com/TMHSDigital/spackle/internal/walk"
)

const (
	defaultMaxOutput = 24000
	// maxEcho bounds how much of any one model-supplied value an error
	// message repeats. Error results are not enveloped, so an unbounded
	// echo would let a model (or text that steered it) write long
	// passages into Spackle's own voice.
	maxEcho = 80
	// maxErrorBytes bounds a whole error result.
	maxErrorBytes = 600
)

// Env is what tools may touch.
type Env struct {
	Root      string           // absolute path of the target root
	Sealer    *envelope.Sealer // wraps every result as untrusted data
	MaxOutput int              // max bytes of content per result; 0 means 24000
	Walk      walk.Options     // configured path exclusions and inclusions
}

// Tool is one callable tool.
type Tool interface {
	Def() llm.ToolDef
	// Run executes with raw JSON args. A returned error is shown to the model as a tool error.
	Run(ctx context.Context, args json.RawMessage) (string, error)
}

// labeled is implemented by the built-in tools so the envelope can name
// what was read (for example "read_file app/db.py"). Tools without it are
// labeled with their name alone.
type labeled interface {
	runLabeled(ctx context.Context, args json.RawMessage) (label, text string, err error)
}

// builtin adapts a function to Tool.
type builtin struct {
	def llm.ToolDef
	fn  func(ctx context.Context, args json.RawMessage) (label, text string, err error)
}

func (b builtin) Def() llm.ToolDef { return b.def }

func (b builtin) Run(ctx context.Context, args json.RawMessage) (string, error) {
	_, text, err := b.fn(ctx, args)
	return text, err
}

func (b builtin) runLabeled(ctx context.Context, args json.RawMessage) (label, text string, err error) {
	return b.fn(ctx, args)
}

// Registry holds the tools one investigator may call.
type Registry struct {
	env      Env
	realRoot string // Root with symlinks resolved, the base walk.Resolve uses
	rootErr  error
	tools    map[string]Tool

	mu       sync.Mutex
	listed   bool
	list     []walk.File
	listErr  error
	redacted map[string]string // abs path -> redacted text; "" means the file has no secrets
}

// NewRegistry returns the read-only code tools for env:
// read_file, list_dir, grep, find_symbol, find_references, git_log, git_show.
func NewRegistry(env Env) *Registry {
	r := &Registry{env: env, tools: map[string]Tool{}, redacted: map[string]string{}}
	if env.Sealer == nil {
		// Without a sealer nothing could be marked untrusted, so no result
		// may leave. Call reports this instead of returning bare content.
		r.rootErr = errors.New("the tool environment has no envelope sealer; this is a Spackle bug, stop and report it")
	}
	switch {
	case !filepath.IsAbs(env.Root):
		// A relative or empty root would silently mean the process working
		// directory, which is not the target.
		r.rootErr = errors.New("the tool environment has no absolute target root; this is a Spackle bug, stop and report it")
	default:
		resolved, err := filepath.EvalSymlinks(env.Root)
		if err == nil {
			resolved, err = filepath.Abs(resolved)
		}
		if err != nil {
			r.rootErr = errors.New("the target root cannot be read; no file tools are available in this run")
		}
		r.realRoot = resolved
	}
	for _, t := range []builtin{
		r.readFileTool(), r.listDirTool(), r.grepTool(), r.findSymbolTool(),
		r.findReferencesTool(), r.gitLogTool(), r.gitShowTool(),
	} {
		r.Add(t)
	}
	return r
}

// Add registers an extra tool (used later for http_request). It panics on a duplicate name.
func (r *Registry) Add(t Tool) {
	name := t.Def().Name
	if _, dup := r.tools[name]; dup {
		panic("tools: duplicate tool name " + name)
	}
	r.tools[name] = t
}

// Names returns registered tool names, sorted.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.tools))
	for n := range r.tools {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Defs returns tool definitions sorted by name.
func (r *Registry) Defs() []llm.ToolDef {
	names := r.Names()
	defs := make([]llm.ToolDef, 0, len(names))
	for _, n := range names {
		defs = append(defs, r.tools[n].Def())
	}
	return defs
}

// Call runs one tool call and always returns a result (never an error): unknown tool, invalid
// JSON arguments, unknown argument fields, and tool failures all become IsError results whose
// text tells the model what to do differently.
func (r *Registry) Call(ctx context.Context, call llm.ToolCall) (res llm.ToolResult) {
	res = llm.ToolResult{CallID: call.ID, Name: call.Name}
	fail := func(msg string) llm.ToolResult {
		msg, _ = redact.Apply(clip(msg, maxErrorBytes))
		return llm.ToolResult{CallID: call.ID, Name: call.Name, Content: msg, IsError: true}
	}
	// A bug in one tool must not take down the run. The panic value is not
	// shown: it could carry target content outside an envelope.
	defer func() {
		if p := recover(); p != nil {
			res = fail("the tool failed unexpectedly; try a different request")
		}
	}()

	t, ok := r.tools[call.Name]
	if !ok {
		return fail(fmt.Sprintf("unknown tool %s; the available tools are: %s", quote(call.Name), strings.Join(r.Names(), ", ")))
	}
	if r.env.Sealer == nil {
		return fail(r.rootErr.Error())
	}
	if err := ctx.Err(); err != nil {
		return fail(call.Name + ": the run was cancelled before the tool started")
	}
	args := bytes.TrimSpace(call.Args)
	switch {
	case len(args) == 0:
		args = []byte("{}")
	case args[0] != '{':
		return fail(call.Name + ": arguments must be a JSON object, for example {\"path\": \"src/app.py\"}; send an object with the fields in the tool schema")
	case !json.Valid(args):
		return fail(call.Name + ": arguments are not valid JSON; send one JSON object with the fields in the tool schema")
	}

	label := call.Name
	var text string
	var err error
	if lt, isLabeled := t.(labeled); isLabeled {
		label, text, err = lt.runLabeled(ctx, args)
	} else {
		text, err = t.Run(ctx, args)
	}
	if err != nil {
		return fail(call.Name + ": " + err.Error())
	}
	res.Content = r.env.Sealer.Wrap(label, r.finish(text))
	return res
}

// finish truncates and redacts tool output. The first redaction pass runs
// on the whole text because truncation could otherwise cut a multi-line
// secret (a private key block) in half, and half a block matches no rule.
// The second pass covers anything the truncation note placed next to text.
func (r *Registry) finish(text string) string {
	limit := r.env.MaxOutput
	if limit <= 0 {
		limit = defaultMaxOutput
	}
	text, _ = redact.Apply(text)
	text = truncate(text, limit)
	text, _ = redact.Apply(text)
	return text
}

// truncate cuts text to at most limit bytes, on a line boundary when there
// is one, and says how much was dropped.
func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	cut := strings.LastIndexByte(text[:limit], '\n') + 1
	if cut == 0 {
		// One line longer than the limit: cut inside it, on a rune boundary.
		cut = limit
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
	}
	head := text[:cut]
	if !strings.HasSuffix(head, "\n") {
		head += "\n"
	}
	return head + fmt.Sprintf("[truncated: %d more bytes; narrow the request]\n", len(text)-cut)
}

// files returns the target listing, computed once per Registry.
func (r *Registry) files() ([]walk.File, error) {
	if r.rootErr != nil {
		return nil, r.rootErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.listed {
		res, err := walk.ListWith(r.env.Root, r.env.Walk)
		if err != nil {
			err = errors.New("the target cannot be listed: " + reason(err))
		}
		r.list, r.listErr, r.listed = res.Files, err, true
	}
	return r.list, r.listErr
}

// resolve confines a model-supplied path to the target. It returns the
// absolute path to open and the forward-slash path relative to the root.
func (r *Registry) resolve(p string) (abs, rel string, err error) {
	if r.rootErr != nil {
		return "", "", r.rootErr
	}
	abs, err = walk.Resolve(r.env.Root, p)
	if err != nil {
		return "", "", pathError(p, err)
	}
	rr, rerr := filepath.Rel(r.realRoot, abs)
	if rerr != nil || !walk.Inside(r.realRoot, abs) {
		// Resolve already guarantees this; refuse rather than trust a
		// disagreement between two views of the root.
		return "", "", fmt.Errorf("path %s could not be placed inside the target; pass a path relative to the target root", quote(p))
	}
	return abs, filepath.ToSlash(rr), nil
}

// text returns a file's content with secrets replaced and line numbers
// preserved. Searching and windowing happen on this text, never on the raw
// bytes: otherwise a line from the middle of a private key would be shown
// on its own (no rule matches it out of context), and whether a pattern
// matched inside a secret would leak the secret one question at a time.
func (r *Registry) text(abs string) (string, error) {
	r.mu.Lock()
	cached, known := r.redacted[abs]
	r.mu.Unlock()
	if known && cached != "" {
		return cached, nil
	}
	raw, err := walk.ReadText(abs)
	if err != nil {
		return "", errors.New(reason(err))
	}
	red := redactKeepLines(raw)
	// Only files that contain secrets are kept in memory; the rest are
	// re-read (and re-scanned, in case they changed) on each use.
	r.mu.Lock()
	if red == raw {
		r.redacted[abs] = ""
	} else {
		r.redacted[abs] = red
	}
	r.mu.Unlock()
	return red, nil
}

// redactKeepLines is redact.Apply that keeps every line where it was: a
// secret that spans lines is replaced by its marker followed by the same
// number of newlines.
func redactKeepLines(text string) string {
	ms := redact.Scan(text)
	if len(ms) == 0 {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	for _, m := range ms {
		b.WriteString(text[pos:m.Start])
		b.WriteString(redact.Marker(m.Rule, m.Hash))
		b.WriteString(strings.Repeat("\n", strings.Count(text[m.Start:m.End], "\n")))
		pos = m.End
	}
	b.WriteString(text[pos:])
	return b.String()
}

// decode reads args into v, refusing fields the schema does not name.
func decode(args json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid arguments (%s); send one JSON object with only the fields in the tool schema and the documented types", clip(err.Error(), 150))
	}
	if dec.More() {
		return errors.New("invalid arguments (extra data after the JSON object); send exactly one JSON object")
	}
	return nil
}

// clip cuts s to at most n bytes on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}

// quote renders a model-supplied value for an error message: bounded and
// with control characters escaped so it stays on one line.
func quote(s string) string { return fmt.Sprintf("%q", clip(s, maxEcho)) }

// pathError rewrites a walk.Resolve error so it cannot echo a long path.
func pathError(p string, err error) error {
	msg := err.Error()
	if len(p) > maxEcho {
		msg = clip(strings.ReplaceAll(msg, fmt.Sprintf("%q", p), quote(p)), 200)
	}
	return fmt.Errorf("%s; pass a path relative to the target root, such as src/app.py", clip(msg, 400))
}

// reason reduces an OS error to its cause. The full text names host paths,
// which the model does not need and the provider should not see.
func reason(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return clip(err.Error(), 200)
}

// schema builds a JSON Schema object for tool arguments. props is the body
// of "properties"; required lists the mandatory fields.
func schema(props string, required ...string) json.RawMessage {
	req, err := json.Marshal(append([]string{}, required...))
	if err != nil {
		panic(err) // a slice of strings always encodes
	}
	return json.RawMessage(`{"type":"object","properties":{` + props + `},"required":` + string(req) + `,"additionalProperties":false}`)
}

// NewNetworkRegistry returns a registry with no file tools, for a target
// that is a running application rather than a directory. Tools are added
// with Add (the scope-bound http_request tool). Results are still
// truncated, redacted and enveloped by Call.
func NewNetworkRegistry(sealer *envelope.Sealer) *Registry {
	r := &Registry{env: Env{Sealer: sealer}, tools: map[string]Tool{}, redacted: map[string]string{}}
	if sealer == nil {
		r.rootErr = errors.New("the tool environment has no envelope sealer; this is a Spackle bug, stop and report it")
	}
	return r
}
