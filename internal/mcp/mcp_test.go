package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/engine"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/report"
	"github.com/TMHSDigital/spackle/internal/seed"
)

const waitFor = 60 * time.Second

// lockedBuffer records everything Serve writes, for the transcript check.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// reply is one decoded JSON-RPC response.
type reply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// toolReply is the result of a tools/call request.
type toolReply struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError    bool            `json:"isError"`
	Structured json.RawMessage `json:"structuredContent"`
}

func (r toolReply) text() string {
	if len(r.Content) == 0 {
		return ""
	}
	return r.Content[0].Text
}

// client drives Serve over a pair of pipes, the way an MCP client drives the
// process over stdin and stdout.
type client struct {
	t          *testing.T
	in         *io.PipeWriter
	lines      chan []byte
	done       chan error
	transcript *lockedBuffer
	log        *lockedBuffer
	nextID     int
	closed     bool
}

func start(t *testing.T, opts Options) *client {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &client{
		t: t, in: inW, lines: make(chan []byte, 64), done: make(chan error, 1),
		transcript: &lockedBuffer{}, log: &lockedBuffer{},
	}
	if opts.Log == nil {
		opts.Log = c.log
	}
	if opts.Version == "" {
		opts.Version = "test"
	}
	go func() {
		err := Serve(context.Background(), inR, io.MultiWriter(c.transcript, outW), opts)
		_ = outW.Close()
		c.done <- err
	}()
	go func() {
		defer close(c.lines)
		br := bufio.NewReader(outR)
		for {
			line, err := br.ReadBytes('\n')
			if len(line) > 0 {
				c.lines <- line
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(c.close)
	return c
}

// send writes one raw line.
func (c *client) send(line string) {
	c.t.Helper()
	if _, err := io.WriteString(c.in, line+"\n"); err != nil {
		c.t.Fatalf("write to server: %v", err)
	}
}

// read returns the next reply, checking that it is a well-formed response.
func (c *client) read() reply {
	c.t.Helper()
	select {
	case line, ok := <-c.lines:
		if !ok {
			c.t.Fatal("server closed its output before replying")
		}
		return parseReply(c.t, line)
	case <-time.After(waitFor):
		c.t.Fatal("timed out waiting for a reply")
	}
	return reply{}
}

func parseReply(t *testing.T, line []byte) reply {
	t.Helper()
	var r reply
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("stdout line is not a JSON-RPC response: %v\n%s", err, line)
	}
	if r.JSONRPC != "2.0" {
		t.Fatalf("response without jsonrpc 2.0: %s", line)
	}
	if len(r.ID) == 0 {
		t.Fatalf("response without an id: %s", line)
	}
	if (r.Error == nil) == (len(r.Result) == 0) {
		t.Fatalf("response must have exactly one of result and error: %s", line)
	}
	return r
}

// request sends a request with a fresh id and returns its reply.
func (c *client) request(method string, params any) reply {
	c.t.Helper()
	c.nextID++
	msg := map[string]any{"jsonrpc": "2.0", "id": c.nextID, "method": method}
	if params != nil {
		msg["params"] = params
	}
	b, err := json.Marshal(msg)
	if err != nil {
		c.t.Fatal(err)
	}
	c.send(string(b))
	r := c.read()
	if string(r.ID) != fmt.Sprint(c.nextID) {
		c.t.Fatalf("reply id %s, want %d", r.ID, c.nextID)
	}
	return r
}

// tool calls a tool and returns its result, failing on a protocol error.
func (c *client) tool(name string, args any) toolReply {
	c.t.Helper()
	p := map[string]any{"name": name}
	if args != nil {
		p["arguments"] = args
	}
	r := c.request("tools/call", p)
	if r.Error != nil {
		c.t.Fatalf("tools/call %s: protocol error %d: %s", name, r.Error.Code, r.Error.Message)
	}
	var tr toolReply
	if err := json.Unmarshal(r.Result, &tr); err != nil {
		c.t.Fatalf("tools/call %s: bad result: %v", name, err)
	}
	if len(tr.Content) != 1 || tr.Content[0].Type != "text" {
		c.t.Fatalf("tools/call %s: want one text content block, got %s", name, r.Result)
	}
	return tr
}

// refused calls a tool and requires an isError result mentioning want.
func (c *client) refused(name string, args any, want string) toolReply {
	c.t.Helper()
	tr := c.tool(name, args)
	if !tr.IsError {
		c.t.Fatalf("%s %v: want a refusal, got %s", name, args, tr.text())
	}
	if !strings.Contains(tr.text(), want) {
		c.t.Fatalf("%s %v: refusal %q does not mention %q", name, args, tr.text(), want)
	}
	return tr
}

// close ends the session and checks that Serve returned nil and that every
// line it wrote to its output was a JSON-RPC response.
func (c *client) close() {
	c.t.Helper()
	if c.closed {
		return
	}
	c.closed = true
	_ = c.in.Close()
	deadline := time.After(waitFor)
	for open := true; open; {
		select {
		case _, ok := <-c.lines:
			open = ok
		case <-deadline:
			c.t.Fatal("timed out waiting for the server to stop")
		}
	}
	if err := <-c.done; err != nil {
		c.t.Errorf("Serve returned %v at end of input, want nil", err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(c.transcript.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		parseReply(c.t, []byte(line))
	}
}

// replyCount is the number of lines the server has written so far.
func (c *client) replyCount() int {
	return strings.Count(c.transcript.String(), "\n")
}

// fixture is a root directory with vulnerable source, a state directory
// outside it, and options that scan with the built-in seeders only, so the
// test does not depend on which scanners are installed.
type fixture struct {
	root, outside string
	opts          Options
	scans         *atomic.Int32
	seen          *[]engine.Options
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(root, "app"), outside} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	src := "package app\n\nimport (\n\t\"database/sql\"\n\t\"fmt\"\n)\n\n" +
		"func find(db *sql.DB, name string) (*sql.Rows, error) {\n" +
		"\treturn db.Query(fmt.Sprintf(\"SELECT id FROM users WHERE name = '%s'\", name))\n}\n"
	if err := os.WriteFile(filepath.Join(root, "app", "db.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "other.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.StateDir = filepath.Join(base, "state")

	var mu sync.Mutex
	scans := &atomic.Int32{}
	seen := &[]engine.Options{}
	return fixture{
		root: root, outside: outside, scans: scans, seen: seen,
		opts: Options{
			Roots: []string{root}, Config: cfg,
			Scan: func(ctx context.Context, o engine.Options) (engine.Result, error) {
				n := scans.Add(1)
				mu.Lock()
				*seen = append(*seen, o)
				mu.Unlock()
				o.Seeders = seed.Builtin()
				// Fixed, increasing ids keep run ordering deterministic.
				o.RunID = fmt.Sprintf("20260101-00000%d-aaaaaa", n)
				return engine.Run(ctx, o)
			},
		},
	}
}

// fakeScan returns a Scan function that records its options and returns a
// run with n findings, without touching the disk.
func fakeScan(seen *[]engine.Options, n int) func(context.Context, engine.Options) (engine.Result, error) {
	return func(_ context.Context, o engine.Options) (engine.Result, error) {
		*seen = append(*seen, o)
		run := report.Run{ID: "fake-run", Target: o.Target, Mode: "deterministic", Outcome: "completed"}
		for i := range n {
			run.Findings = append(run.Findings, finding.Finding{
				ID: fmt.Sprintf("SPK-%08d", i), Title: "t", Class: "sql-injection",
				Severity:   finding.Severity{Label: "high", Score: 8.1},
				Confidence: finding.Confidence{Level: finding.ConfidencePlausible},
				Location:   finding.Location{File: "a.go", StartLine: i + 1},
				Status:     finding.StatusOpen,
			})
		}
		return engine.Result{RunID: run.ID, Run: run}, nil
	}
}

func TestInitializeNegotiatesVersion(t *testing.T) {
	c := start(t, Options{Roots: []string{t.TempDir()}, Config: config.Default(), Version: "1.2.3"})
	cases := map[string]string{
		"2025-06-18": "2025-06-18",
		"2025-03-26": "2025-03-26",
		"2024-11-05": "2024-11-05",
		"1999-01-01": ProtocolVersion,
		"":           ProtocolVersion,
	}
	for asked, want := range cases {
		r := c.request("initialize", map[string]any{
			"protocolVersion": asked, "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "test", "version": "0"},
		})
		if r.Error != nil {
			t.Fatalf("initialize %q: %s", asked, r.Error.Message)
		}
		var res struct {
			ProtocolVersion string `json:"protocolVersion"`
			Capabilities    map[string]json.RawMessage
			ServerInfo      struct{ Name, Version string }
			Instructions    string
		}
		if err := json.Unmarshal(r.Result, &res); err != nil {
			t.Fatal(err)
		}
		if res.ProtocolVersion != want {
			t.Errorf("asked %q: got version %q, want %q", asked, res.ProtocolVersion, want)
		}
		if res.ServerInfo.Name != "spackle" || res.ServerInfo.Version != "1.2.3" {
			t.Errorf("serverInfo = %+v", res.ServerInfo)
		}
		if len(res.Capabilities) != 1 || res.Capabilities["tools"] == nil {
			t.Errorf("capabilities must offer tools only, got %v", res.Capabilities)
		}
		if res.Instructions == "" {
			t.Error("no instructions")
		}
	}
}

func TestToolsListShape(t *testing.T) {
	c := start(t, Options{Roots: []string{t.TempDir()}, Config: config.Default()})
	r := c.request("tools/list", nil)
	if r.Error != nil {
		t.Fatal(r.Error.Message)
	}
	var res struct {
		Tools []struct {
			Name        string
			Title       string
			Description string
			InputSchema struct {
				Type                 string
				Properties           map[string]json.RawMessage
				Required             []string
				AdditionalProperties *bool
			}
			Annotations map[string]bool
		}
	}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
		if tl.Title == "" || tl.Description == "" {
			t.Errorf("%s: missing title or description", tl.Name)
		}
		s := tl.InputSchema
		if s.Type != "object" || s.Properties == nil {
			t.Errorf("%s: schema must be an object with properties", tl.Name)
		}
		if s.AdditionalProperties == nil || *s.AdditionalProperties {
			t.Errorf("%s: schema must set additionalProperties to false", tl.Name)
		}
		for _, req := range s.Required {
			if _, ok := s.Properties[req]; !ok {
				t.Errorf("%s: required %q is not a property", tl.Name, req)
			}
		}
		for _, hint := range []string{"readOnlyHint", "openWorldHint"} {
			if _, ok := tl.Annotations[hint]; !ok {
				t.Errorf("%s: missing annotation %s", tl.Name, hint)
			}
		}
		if tl.Annotations["openWorldHint"] {
			t.Errorf("%s: openWorldHint must be false when no model is allowed", tl.Name)
		}
		if wantRO := tl.Name != "scan"; tl.Annotations["readOnlyHint"] != wantRO {
			t.Errorf("%s: readOnlyHint = %v, want %v", tl.Name, !wantRO, wantRO)
		}
		if strings.ToLower(tl.Name) != tl.Name || strings.HasPrefix(tl.Name, "spackle") {
			t.Errorf("%s: tool names are lowercase snake_case with no server prefix", tl.Name)
		}
	}
	want := []string{"compare_runs", "doctor", "get_finding", "get_report", "list_runs", "scan"}
	if !slices.Equal(names, want) {
		t.Errorf("tools = %v, want %v", names, want)
	}
	if !slices.IsSorted(names) {
		t.Errorf("tools are not sorted: %v", names)
	}
}

func TestToolsListSaysWhenModelCallsAreAllowed(t *testing.T) {
	cfg := config.Default()
	cfg.Model = config.Model{Provider: config.ProviderOllama, Model: "m"}
	c := start(t, Options{Roots: []string{t.TempDir()}, Config: cfg, AllowModel: true})
	r := c.request("tools/list", nil)
	var res struct {
		Tools []struct {
			Name        string
			Annotations map[string]bool
		}
	}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		if want := tl.Name == "scan" || tl.Name == "doctor"; tl.Annotations["openWorldHint"] != want {
			t.Errorf("%s: openWorldHint = %v, want %v", tl.Name, !want, want)
		}
	}
}

func TestProtocolBasics(t *testing.T) {
	c := start(t, Options{Roots: []string{t.TempDir()}, Config: config.Default()})

	if r := c.request("ping", nil); r.Error != nil || string(r.Result) != "{}" {
		t.Errorf("ping = %s, %v", r.Result, r.Error)
	}

	// Notifications, known or not, well-formed or not, are never answered.
	before := c.replyCount()
	c.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	c.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99}}`)
	c.send(`{"jsonrpc":"2.0","method":"no/such/notification"}`)
	c.send(`{"jsonrpc":"1.0","method":"notifications/initialized"}`)
	c.send(``)
	if r := c.request("ping", nil); r.Error != nil {
		t.Fatalf("ping after notifications: %s", r.Error.Message)
	}
	if got := c.replyCount() - before; got != 1 {
		t.Errorf("%d replies after four notifications and one ping, want 1", got)
	}

	if r := c.request("resources/list", nil); r.Error == nil || r.Error.Code != codeMethodNotFound {
		t.Errorf("unknown method: got %+v, want %d", r.Error, codeMethodNotFound)
	}

	c.send(`{"jsonrpc":"2.0","id":1,"method":`)
	if r := c.read(); r.Error == nil || r.Error.Code != codeParse || string(r.ID) != "null" {
		t.Errorf("malformed JSON: got %+v id %s, want %d with a null id", r.Error, r.ID, codeParse)
	}

	c.send(`{"id":7,"method":"ping"}`)
	if r := c.read(); r.Error == nil || r.Error.Code != codeInvalidRequest || string(r.ID) != "7" {
		t.Errorf("missing jsonrpc: got %+v, want %d", r.Error, codeInvalidRequest)
	}

	c.send(`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`)
	if r := c.read(); r.Error == nil || r.Error.Code != codeInvalidRequest {
		t.Errorf("batch: got %+v, want %d", r.Error, codeInvalidRequest)
	}

	if r := c.request("tools/call", map[string]any{"name": "spackle_scan"}); r.Error == nil || r.Error.Code != codeInvalidParams {
		t.Errorf("unknown tool: got %+v, want %d", r.Error, codeInvalidParams)
	}
	if r := c.request("tools/call", "not an object"); r.Error == nil || r.Error.Code != codeInvalidParams {
		t.Errorf("bad tools/call params: got %+v, want %d", r.Error, codeInvalidParams)
	}

	// The session survived all of the above.
	if r := c.request("ping", nil); r.Error != nil {
		t.Errorf("ping at the end: %s", r.Error.Message)
	}
}

func TestUnknownArgumentIsRefused(t *testing.T) {
	fx := newFixture(t)
	c := start(t, fx.opts)
	c.refused("scan", map[string]any{"path": ".", "depth": 3}, `unknown field "depth"`)
	c.refused("list_runs", map[string]any{"limit": 5}, `unknown field "limit"`)
	c.refused("doctor", map[string]any{"fix": true}, `unknown field "fix"`)
	c.refused("get_report", map[string]any{"run_id": "latest", "out": "x"}, `unknown field "out"`)
	c.refused("get_finding", map[string]any{"run_id": "latest", "finding_id": "x", "raw": true}, `unknown field "raw"`)
	c.refused("scan", []string{"."}, "invalid arguments")
	c.refused("scan", map[string]any{"path": 5}, "invalid arguments")
	c.refused("scan", map[string]any{}, "needs a path")
	if n := fx.scans.Load(); n != 0 {
		t.Errorf("Scan ran %d times for refused arguments", n)
	}
}

func TestOperatorSettingsAreNotArguments(t *testing.T) {
	fx := newFixture(t)
	c := start(t, fx.opts)
	for name, value := range map[string]any{
		"model": "big-model", "provider": "anthropic", "budget_usd": 500, "offline": false,
		"base_url": "http://203.0.113.5/v1", "budget_tokens": 9, "out": "/tmp/x", "allow_model": true, "root": "/",
	} {
		tr := c.refused("scan", map[string]any{"path": ".", name: value}, fmt.Sprintf("unknown field %q", name))
		if !strings.Contains(tr.text(), "set by the operator") {
			t.Errorf("%s: refusal does not say who sets it: %s", name, tr.text())
		}
	}
	if n := fx.scans.Load(); n != 0 {
		t.Errorf("Scan ran %d times for refused arguments", n)
	}
}

func TestScanFindsAFlawAndStoresTheRun(t *testing.T) {
	fx := newFixture(t)
	c := start(t, fx.opts)
	tr := c.tool("scan", map[string]any{"path": "."})
	if tr.IsError {
		t.Fatalf("scan failed: %s", tr.text())
	}
	var sum scanSummary
	if err := json.Unmarshal(tr.Structured, &sum); err != nil {
		t.Fatal(err)
	}
	var fromText scanSummary
	if err := json.Unmarshal([]byte(tr.text()), &fromText); err != nil {
		t.Fatalf("text is not the same JSON as structuredContent: %v", err)
	}
	if fromText.RunID != sum.RunID || len(fromText.Findings) != len(sum.Findings) {
		t.Error("text and structuredContent differ")
	}
	if sum.RunID == "" || sum.Mode != "deterministic" || sum.Outcome != "completed" {
		t.Errorf("summary = %+v", sum)
	}
	i := slices.IndexFunc(sum.Findings, func(f findingRow) bool { return f.Class == "sql-injection" })
	if i < 0 {
		t.Fatalf("no sql-injection finding in %+v", sum.Findings)
	}
	f := sum.Findings[i]
	if f.ID == "" || f.Title == "" || f.Severity == "" || f.Confidence == "" || f.Status != finding.StatusOpen {
		t.Errorf("incomplete finding row: %+v", f)
	}
	if !strings.HasPrefix(f.Location, "app/db.go:") {
		t.Errorf("location = %q, want a forward-slash path under app/", f.Location)
	}
	if sum.TotalFindings != len(sum.Findings) || sum.Omitted != 0 {
		t.Errorf("total %d, listed %d, omitted %d", sum.TotalFindings, len(sum.Findings), sum.Omitted)
	}
	if got := sum.Counts.Critical + sum.Counts.High + sum.Counts.Medium + sum.Counts.Low + sum.Counts.None; got != sum.TotalFindings {
		t.Errorf("counts add up to %d, want %d", got, sum.TotalFindings)
	}
	ledger := filepath.Join(engine.RunsDir(fx.opts.Config.StateDir), sum.RunID, "ledger.jsonl")
	if _, err := os.Stat(ledger); err != nil {
		t.Errorf("no run directory was written: %v", err)
	}

	// The engine is called without a Confirm hook and with the resolved root.
	o := (*fx.seen)[0]
	if o.Confirm != nil {
		t.Error("Confirm must be nil: nobody can answer a prompt over MCP")
	}
	wantRoot, err := filepath.EvalSymlinks(fx.root)
	if err != nil {
		t.Fatal(err)
	}
	if o.Target != wantRoot {
		t.Errorf("engine target = %q, want %q", o.Target, wantRoot)
	}

	// An absolute path inside the root and a subdirectory both work.
	if tr := c.tool("scan", map[string]any{"path": filepath.Join(fx.root, "app")}); tr.IsError {
		t.Errorf("absolute path inside the root refused: %s", tr.text())
	}
	if tr := c.tool("scan", map[string]any{"path": "app"}); tr.IsError {
		t.Errorf("relative subdirectory refused: %s", tr.text())
	}
}

func TestScanRefusesEverythingButADirectoryInsideARoot(t *testing.T) {
	fx := newFixture(t)
	c := start(t, fx.opts)
	cases := []struct{ path, want string }{
		{fx.outside, "outside the directories"},
		{"..", "outside the directories"},
		{filepath.Join("app", "..", "..", "outside"), "outside the directories"},
		{filepath.Dir(fx.root), "outside the directories"},
		{"http://127.0.0.1:8080/", "only local directories"},
		{"https://staging.example.test/login", "only local directories"},
		{"https://github.com/example/repo.git", "only local directories"},
		{"git@github.com:example/repo.git", "only local directories"},
		{"ssh://git@example.test/repo.git", "only local directories"},
		{"file:///etc", "only local directories"},
		{"no-such-directory", "does not exist"},
		{filepath.Join("app", "db.go"), "not a directory"},
		{"", "empty"},
		{"   ", "empty"},
		{"a\x00b", "NUL"},
	}
	for _, tc := range cases {
		tr := c.refused("scan", map[string]any{"path": tc.path}, tc.want)
		if len(tr.Structured) != 0 {
			t.Errorf("%q: a refusal must not carry structuredContent", tc.path)
		}
	}
	// The refusal for a remote target says where such scans can be run.
	c.refused("scan", map[string]any{"path": "http://127.0.0.1:8080/"}, "command line")
	if n := fx.scans.Load(); n != 0 {
		t.Errorf("Scan ran %d times for refused targets", n)
	}
	if _, err := os.Stat(engine.RunsDir(fx.opts.Config.StateDir)); !os.IsNotExist(err) {
		t.Errorf("a refused scan left a runs directory behind (stat error: %v)", err)
	}
}

func TestScanRefusesASymlinkThatLeavesTheRoot(t *testing.T) {
	fx := newFixture(t)
	link := filepath.Join(fx.root, "link")
	if err := os.Symlink(fx.outside, link); err != nil {
		t.Skipf("symlinks cannot be created on this machine: %v", err)
	}
	c := start(t, fx.opts)
	c.refused("scan", map[string]any{"path": "link"}, "outside the directories")
	c.refused("scan", map[string]any{"path": link}, "outside the directories")
	if n := fx.scans.Load(); n != 0 {
		t.Errorf("Scan ran %d times through an escaping symlink", n)
	}
}

func TestScanAcceptsASecondRoot(t *testing.T) {
	fx := newFixture(t)
	fx.opts.Roots = []string{fx.root, fx.outside}
	c := start(t, fx.opts)
	if tr := c.tool("scan", map[string]any{"path": fx.outside}); tr.IsError {
		t.Errorf("a directory in the second root was refused: %s", tr.text())
	}
}

func TestModelIsStrippedWithoutAllowModel(t *testing.T) {
	model := config.Model{Provider: config.ProviderAnthropic, Model: "some-model"}
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow=%v", allow), func(t *testing.T) {
			var seen []engine.Options
			cfg := config.Default()
			cfg.Model = model
			cfg.Stages = map[string]config.Model{"reviewer": model}
			cfg.Offline = true
			c := start(t, Options{Roots: []string{t.TempDir()}, Config: cfg, AllowModel: allow, Scan: fakeScan(&seen, 1)})
			if tr := c.tool("scan", map[string]any{"path": "."}); tr.IsError {
				t.Fatal(tr.text())
			}
			if len(seen) != 1 {
				t.Fatalf("Scan ran %d times", len(seen))
			}
			got := seen[0].Config
			if allow {
				if got.Model != model || len(got.Stages) != 1 {
					t.Errorf("with AllowModel the operator's model must reach the engine, got %+v %v", got.Model, got.Stages)
				}
			} else if got.Model.Configured() || got.Model != (config.Model{}) || len(got.Stages) != 0 {
				t.Errorf("without AllowModel the engine must get no model, got %+v %v", got.Model, got.Stages)
			}
			if !got.Offline || got.Budget != cfg.Budget {
				t.Errorf("operator settings changed on the way to the engine: %+v", got)
			}
		})
	}
}

func TestMaxFindingsOnlyLowersTheLimit(t *testing.T) {
	var seen []engine.Options
	cfg := config.Default()
	cfg.Budget.MaxFindings = 10
	c := start(t, Options{Roots: []string{t.TempDir()}, Config: cfg, Scan: fakeScan(&seen, 30)})

	for _, bad := range []any{0, -1, 101, 1.5, "5"} {
		c.refused("scan", map[string]any{"path": ".", "max_findings": bad}, "max_findings")
	}
	if len(seen) != 0 {
		t.Fatalf("Scan ran for an invalid max_findings")
	}

	for arg, want := range map[int]int{3: 3, 10: 10, 100: 10} {
		seen = seen[:0]
		if tr := c.tool("scan", map[string]any{"path": ".", "max_findings": arg}); tr.IsError {
			t.Fatal(tr.text())
		}
		if got := seen[0].Config.Budget.MaxFindings; got != want {
			t.Errorf("max_findings %d: engine limit %d, want %d", arg, got, want)
		}
	}

	// The summary lists at most 25 findings and says how many it left out.
	tr := c.tool("scan", map[string]any{"path": "."})
	var sum scanSummary
	if err := json.Unmarshal(tr.Structured, &sum); err != nil {
		t.Fatal(err)
	}
	if len(sum.Findings) != 25 || sum.TotalFindings != 30 || sum.Omitted != 5 || sum.Note == "" {
		t.Errorf("listed %d of %d, omitted %d, note %q", len(sum.Findings), sum.TotalFindings, sum.Omitted, sum.Note)
	}
	if sum.Counts.High != 30 {
		t.Errorf("counts cover every finding, not only the listed ones: %+v", sum.Counts)
	}
}

func TestScanErrorsAreToolErrors(t *testing.T) {
	fail := func(err error) func(context.Context, engine.Options) (engine.Result, error) {
		return func(context.Context, engine.Options) (engine.Result, error) { return engine.Result{}, err }
	}
	c := start(t, Options{Roots: []string{t.TempDir()}, Config: config.Default(), Scan: fail(fmt.Errorf("%w: no key", engine.ErrRefused))})
	c.refused("scan", map[string]any{"path": "."}, "scan refused")
	c2 := start(t, Options{Roots: []string{t.TempDir()}, Config: config.Default(), Scan: fail(fmt.Errorf("disk full"))})
	c2.refused("scan", map[string]any{"path": "."}, "scan failed: disk full")
}

func TestGetReportAndGetFinding(t *testing.T) {
	fx := newFixture(t)
	c := start(t, fx.opts)

	// With no runs, the lookup fails with a message, not a crash.
	c.refused("get_report", map[string]any{"run_id": "latest"}, "no runs found")

	tr := c.tool("scan", map[string]any{"path": "."})
	var sum scanSummary
	if err := json.Unmarshal(tr.Structured, &sum); err != nil || len(sum.Findings) == 0 {
		t.Fatalf("scan: %v %s", err, tr.text())
	}
	fid := sum.Findings[0].ID

	for _, format := range []string{"", "markdown", "json", "sarif"} {
		args := map[string]any{"run_id": sum.RunID}
		if format != "" {
			args["format"] = format
		}
		tr := c.tool("get_report", args)
		if tr.IsError {
			t.Fatalf("get_report %q: %s", format, tr.text())
		}
		if !strings.HasPrefix(tr.text(), dataNotice+"\n\n") {
			t.Errorf("get_report %q does not start with the data notice", format)
		}
		var rr reportResult
		if err := json.Unmarshal(tr.Structured, &rr); err != nil {
			t.Fatal(err)
		}
		wantFormat := format
		if wantFormat == "" {
			wantFormat = "markdown"
		}
		if rr.Format != wantFormat || rr.RunID != sum.RunID || rr.Truncated || rr.Notice != dataNotice {
			t.Errorf("get_report %q: %+v", format, rr)
		}
		if tr.text() != dataNotice+"\n\n"+rr.Report {
			t.Errorf("get_report %q: text and structuredContent differ", format)
		}
		if !strings.Contains(rr.Report, fid) {
			t.Errorf("get_report %q does not mention finding %s", format, fid)
		}
		if wantFormat != "markdown" && !json.Valid([]byte(rr.Report)) {
			t.Errorf("get_report %q is not valid JSON", format)
		}
	}
	// "latest" and a unique prefix resolve to the same run.
	for _, id := range []string{"latest", sum.RunID[:12]} {
		if tr := c.tool("get_report", map[string]any{"run_id": id}); tr.IsError {
			t.Errorf("get_report %q: %s", id, tr.text())
		}
	}
	for _, bad := range []string{"html", "terminal", "pdf", "MARKDOWN", "md"} {
		c.refused("get_report", map[string]any{"run_id": sum.RunID, "format": bad}, "unknown report format")
	}
	c.refused("get_report", map[string]any{}, "needs a run_id")
	c.refused("get_report", map[string]any{"run_id": "19990101"}, "not found")

	ft := c.tool("get_finding", map[string]any{"run_id": sum.RunID, "finding_id": fid})
	if ft.IsError {
		t.Fatalf("get_finding: %s", ft.text())
	}
	body, ok := strings.CutPrefix(ft.text(), dataNotice+"\n\n")
	if !ok {
		t.Fatal("get_finding does not start with the data notice")
	}
	var f finding.Finding
	if err := json.Unmarshal([]byte(body), &f); err != nil {
		t.Fatalf("get_finding text is not the finding JSON: %v", err)
	}
	if f.ID != fid || f.Class == "" || f.Flaw.Description == "" || f.Remediation.Summary == "" {
		t.Errorf("get_finding returned an incomplete finding: %+v", f)
	}
	var fr findingResult
	if err := json.Unmarshal(ft.Structured, &fr); err != nil || fr.Finding.ID != fid || fr.Notice != dataNotice {
		t.Errorf("get_finding structuredContent: %v %+v", err, fr)
	}

	c.refused("get_finding", map[string]any{"run_id": sum.RunID, "finding_id": "SPK-00000000"}, "is not in run")
	c.refused("get_finding", map[string]any{"run_id": sum.RunID, "finding_id": ""}, "finding_id")
	c.refused("get_finding", map[string]any{"run_id": sum.RunID}, "needs a run_id and a finding_id")
}

func TestRunIDCannotNameAPath(t *testing.T) {
	fx := newFixture(t)
	c := start(t, fx.opts)
	if tr := c.tool("scan", map[string]any{"path": "."}); tr.IsError {
		t.Fatal(tr.text())
	}
	for _, id := range []string{"../x", "a/b", `a\b`, "..", `..\..\state`, "/", "2026..", "a\x00b", strings.Repeat("a", 200), "", "  "} {
		for tool, args := range map[string]map[string]any{
			"get_report":  {"run_id": id},
			"get_finding": {"run_id": id, "finding_id": "SPK-00000000"},
		} {
			tr := c.refused(tool, args, "run_id ")
			if strings.Contains(tr.text(), "invalid arguments") || strings.Contains(tr.text(), "not found") || strings.Contains(tr.text(), "is not in run") {
				t.Errorf("%s %q was not refused as a run id: %s", tool, id, tr.text())
			}
		}
	}
}

func TestListRuns(t *testing.T) {
	fx := newFixture(t)
	c := start(t, fx.opts)

	var list runList
	tr := c.tool("list_runs", nil)
	if err := json.Unmarshal(tr.Structured, &list); err != nil || tr.IsError {
		t.Fatalf("list_runs with no runs: %v %s", err, tr.text())
	}
	if len(list.Runs) != 0 || !strings.Contains(tr.text(), `"runs":[]`) {
		t.Errorf("want an empty list, got %s", tr.text())
	}

	var ids []string
	for range 3 {
		var sum scanSummary
		tr := c.tool("scan", map[string]any{"path": "."})
		if err := json.Unmarshal(tr.Structured, &sum); err != nil || tr.IsError {
			t.Fatalf("scan: %v %s", err, tr.text())
		}
		ids = append(ids, sum.RunID)
	}
	// A directory that is not a readable run is listed with its error.
	broken := "20270101-000000-broken"
	if err := os.MkdirAll(filepath.Join(engine.RunsDir(fx.opts.Config.StateDir), broken), 0o750); err != nil {
		t.Fatal(err)
	}

	tr = c.tool("list_runs", map[string]any{})
	if err := json.Unmarshal(tr.Structured, &list); err != nil || tr.IsError {
		t.Fatalf("list_runs: %v %s", err, tr.text())
	}
	var got []string
	for _, r := range list.Runs {
		got = append(got, r.RunID)
	}
	want := []string{broken, ids[2], ids[1], ids[0]}
	if !slices.Equal(got, want) {
		t.Fatalf("runs = %v, want newest first %v", got, want)
	}
	if list.Total != 4 || list.Omitted != 0 {
		t.Errorf("total %d omitted %d", list.Total, list.Omitted)
	}
	if b := list.Runs[0]; b.Error == "" || b.Findings != nil || b.Counts != nil {
		t.Errorf("the unreadable run must carry an error and nothing else: %+v", b)
	}
	for _, r := range list.Runs[1:] {
		if r.Error != "" || r.Target == "" || r.Outcome != "completed" || r.Findings == nil || *r.Findings == 0 || r.Counts == nil {
			t.Errorf("incomplete row: %+v", r)
		}
		if _, err := time.Parse(time.RFC3339, r.Started); err != nil {
			t.Errorf("started %q is not RFC 3339: %v", r.Started, err)
		}
	}
}

func TestListRunsCapsAtFifty(t *testing.T) {
	cfg := config.Default()
	cfg.StateDir = t.TempDir()
	for i := range 55 {
		if err := os.MkdirAll(filepath.Join(engine.RunsDir(cfg.StateDir), fmt.Sprintf("20260101-0000%02d-aaaaaa", i)), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	c := start(t, Options{Roots: []string{t.TempDir()}, Config: cfg})
	var list runList
	tr := c.tool("list_runs", nil)
	if err := json.Unmarshal(tr.Structured, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Runs) != 50 || list.Total != 55 || list.Omitted != 5 {
		t.Errorf("listed %d, total %d, omitted %d", len(list.Runs), list.Total, list.Omitted)
	}
	if list.Runs[0].RunID != "20260101-000054-aaaaaa" {
		t.Errorf("first run is %s, want the newest", list.Runs[0].RunID)
	}
}

func TestDoctor(t *testing.T) {
	rows := []Check{{"Tools", "git", "ok", "available"}, {"Sandbox", "runtime", "missing", "no runtime"}}
	c := start(t, Options{
		Roots: []string{t.TempDir()}, Config: config.Default(),
		Doctor: func(context.Context) []Check { return rows },
	})
	tr := c.tool("doctor", nil)
	if tr.IsError {
		t.Fatal(tr.text())
	}
	var got struct {
		Checks []map[string]string `json:"checks"`
	}
	if err := json.Unmarshal(tr.Structured, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Checks) != 2 {
		t.Fatalf("checks = %v", got.Checks)
	}
	want := map[string]string{"area": "Sandbox", "name": "runtime", "status": "missing", "note": "no runtime"}
	if fmt.Sprint(got.Checks[1]) != fmt.Sprint(want) {
		t.Errorf("row = %v, want %v", got.Checks[1], want)
	}
	if !json.Valid([]byte(tr.text())) {
		t.Error("doctor text is not JSON")
	}

	none := start(t, Options{Roots: []string{t.TempDir()}, Config: config.Default()})
	none.refused("doctor", nil, "not available")
}

func TestOversizedMessageIsRejected(t *testing.T) {
	c := start(t, Options{Roots: []string{t.TempDir()}, Config: config.Default()})
	big := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"` + strings.Repeat("a", maxMessage) + `"}}`
	c.send(big)
	r := c.read()
	if r.Error == nil || r.Error.Code != codeParse || !strings.Contains(r.Error.Message, "too large") {
		t.Fatalf("oversized message: got %+v", r.Error)
	}
	if r := c.request("ping", nil); r.Error != nil {
		t.Errorf("the session did not survive an oversized message: %s", r.Error.Message)
	}
}

func TestToolCallsRunOneAtATime(t *testing.T) {
	var active, peak atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{}, 8)
	c := start(t, Options{
		Roots: []string{t.TempDir()}, Config: config.Default(),
		Scan: func(context.Context, engine.Options) (engine.Result, error) {
			n := active.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			started <- struct{}{}
			<-release
			active.Add(-1)
			return engine.Result{RunID: "r"}, nil
		},
	})
	for id := 1; id <= 3; id++ {
		c.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"scan","arguments":{"path":"."}}}`, id))
	}
	<-started
	// A request that is not a tool call is answered while a scan runs.
	c.send(`{"jsonrpc":"2.0","id":"p","method":"ping"}`)
	if r := c.read(); string(r.ID) != `"p"` || r.Error != nil {
		t.Fatalf("ping during a scan: id %s error %+v", r.ID, r.Error)
	}
	// Reusing the id of a running request is refused.
	c.send(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	dup := c.read()
	close(release)
	if string(dup.ID) != "1" || dup.Error == nil || dup.Error.Code != codeInvalidRequest {
		t.Errorf("duplicate id: got id %s error %+v", dup.ID, dup.Error)
	}
	for range 3 {
		if r := c.read(); r.Error != nil {
			t.Errorf("scan reply: %+v", r.Error)
		}
	}
	if p := peak.Load(); p != 1 {
		t.Errorf("%d scans ran at once, want 1", p)
	}
}

func TestCancelledNotificationStopsACall(t *testing.T) {
	started := make(chan struct{})
	c := start(t, Options{
		Roots: []string{t.TempDir()}, Config: config.Default(),
		Scan: func(ctx context.Context, _ engine.Options) (engine.Result, error) {
			close(started)
			<-ctx.Done()
			return engine.Result{}, ctx.Err()
		},
	})
	c.send(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"scan","arguments":{"path":"."}}}`)
	<-started
	c.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":5}}`)
	r := c.read()
	var tr toolReply
	if err := json.Unmarshal(r.Result, &tr); err != nil || !tr.IsError || !strings.Contains(tr.text(), "cancelled") {
		t.Errorf("cancelled scan: %v %s", err, r.Result)
	}
}

func TestPanicInAToolIsAnInternalError(t *testing.T) {
	c := start(t, Options{
		Roots: []string{t.TempDir()}, Config: config.Default(),
		Scan: func(context.Context, engine.Options) (engine.Result, error) { panic("boom") },
	})
	r := c.request("tools/call", map[string]any{"name": "scan", "arguments": map[string]any{"path": "."}})
	if r.Error == nil || r.Error.Code != codeInternal {
		t.Fatalf("got %+v, want %d", r.Error, codeInternal)
	}
	if strings.Contains(r.Error.Message, "boom") {
		t.Error("the panic value must go to the log, not to the client")
	}
	if !strings.Contains(c.log.String(), "boom") {
		t.Error("the panic value was not logged")
	}
	if r := c.request("ping", nil); r.Error != nil {
		t.Errorf("the session did not survive a panic: %s", r.Error.Message)
	}
}

func TestServeRejectsBadRoots(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{filepath.Join(dir, "missing"), file} {
		var out bytes.Buffer
		err := Serve(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out, Options{Roots: []string{root}, Config: config.Default()})
		if err == nil || !strings.Contains(err.Error(), "--root") {
			t.Errorf("root %q: got %v, want an error that names --root", root, err)
		}
		if out.Len() != 0 {
			t.Errorf("root %q: the server answered a request despite a bad root", root)
		}
	}
}

func TestServeDefaultsToTheWorkingDirectoryAndEndsAtEOF(t *testing.T) {
	var out, log bytes.Buffer
	// The last line has no newline: it is still answered before Serve ends.
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if err := Serve(context.Background(), in, &out, Options{Config: config.Default(), Log: &log}); err != nil {
		t.Fatalf("Serve = %v, want nil at EOF", err)
	}
	if n := strings.Count(out.String(), "\n"); n != 2 {
		t.Errorf("%d replies, want 2: %s", n, out.String())
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), filepath.Base(wd)) || !strings.Contains(log.String(), "deterministic stages only") {
		t.Errorf("the start-up line does not name the root and the model mode: %s", log.String())
	}
}

func TestServeStopsWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	inR, inW := io.Pipe()
	defer func() { _ = inW.Close() }()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, inR, io.Discard, Options{Roots: []string{t.TempDir()}, Config: config.Default()})
	}()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Serve returned nil for a cancelled context, want the context error")
		}
	case <-time.After(waitFor):
		t.Fatal("Serve did not stop")
	}
}

func TestTruncate(t *testing.T) {
	if got, cut := truncate("abc", 3); got != "abc" || cut {
		t.Errorf("truncate at the limit = %q, %v", got, cut)
	}
	if got, cut := truncate("abcd", 3); got != "abc" || !cut {
		t.Errorf("truncate over the limit = %q, %v", got, cut)
	}
	// A cut never lands inside a multi-byte character.
	s := "ab" + string(rune(0x20AC)) + "cd" // the euro sign is three bytes
	if got, cut := truncate(s, 4); got != "ab" || !cut {
		t.Errorf("truncate inside a rune = %q, %v", got, cut)
	}
}

func TestGetReportTruncatesLargeReports(t *testing.T) {
	fx := newFixture(t)
	// Enough flawed lines to push the JSON report past the cap.
	var src strings.Builder
	src.WriteString("package app\n\nimport (\n\t\"database/sql\"\n\t\"fmt\"\n)\n\nfunc many(db *sql.DB, name string) {\n")
	for range 400 {
		src.WriteString("\t_, _ = db.Query(fmt.Sprintf(\"SELECT id FROM users WHERE name = '%s'\", name))\n")
	}
	src.WriteString("}\n")
	if err := os.WriteFile(filepath.Join(fx.root, "app", "many.go"), []byte(src.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	fx.opts.Config.Budget.MaxFindings = 1000
	c := start(t, fx.opts)
	if tr := c.tool("scan", map[string]any{"path": "."}); tr.IsError {
		t.Fatal(tr.text())
	}
	tr := c.tool("get_report", map[string]any{"run_id": "latest", "format": "json"})
	var rr reportResult
	if err := json.Unmarshal(tr.Structured, &rr); err != nil || tr.IsError {
		t.Fatalf("get_report: %v", err)
	}
	if rr.TotalBytes <= maxReportBytes {
		t.Skipf("the report is only %d bytes, so truncation is not exercised", rr.TotalBytes)
	}
	if !rr.Truncated || len(rr.Report) > maxReportBytes {
		t.Errorf("truncated=%v with %d bytes, want at most %d", rr.Truncated, len(rr.Report), maxReportBytes)
	}
	if !strings.Contains(tr.text(), "[Truncated: the report is") {
		t.Error("the text does not carry the truncation note")
	}
}

// The run summary and the finding folders are shortcuts. list_runs and
// get_finding must say exactly the same with them as from the ledger, and
// must fall back to the ledger when a summary is missing or out of date.
func TestRunSummaryShortcutAgreesWithTheLedger(t *testing.T) {
	fx := newFixture(t)
	c := start(t, fx.opts)
	var sum scanSummary
	tr := c.tool("scan", map[string]any{"path": "."})
	if err := json.Unmarshal(tr.Structured, &sum); err != nil || tr.IsError || len(sum.Findings) == 0 {
		t.Fatalf("scan: %v %s", err, tr.text())
	}
	fid := sum.Findings[0].ID
	runDir := filepath.Join(engine.RunsDir(fx.opts.Config.StateDir), sum.RunID)
	summary := filepath.Join(runDir, report.SummaryFile)
	if _, ok := report.LoadSummary(runDir); !ok {
		t.Fatal("the scan left no current run summary, so this test would compare the ledger with itself")
	}
	if f, id, ok := storedFinding(runDir, strings.ToLower(fid)); !ok || f.ID != fid || id != sum.RunID {
		t.Fatalf("the stored finding was not used: %v %q %q", ok, f.ID, id)
	}
	for _, id := range []string{"SPK-00000000", "../" + fid, "SPK-123", ""} {
		if _, _, ok := storedFinding(runDir, id); ok {
			t.Errorf("storedFinding accepted %q", id)
		}
	}

	ask := func() (list, one string) {
		t.Helper()
		l := c.tool("list_runs", nil)
		f := c.tool("get_finding", map[string]any{"run_id": sum.RunID, "finding_id": fid})
		if l.IsError || f.IsError {
			t.Fatalf("list_runs: %s\nget_finding: %s", l.text(), f.text())
		}
		return l.text(), f.text()
	}
	listFast, findingFast := ask()

	// Out of date: the ledger grew after the summary was written.
	raw, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	stale := strings.Replace(string(raw), `"outcome": "completed"`, `"outcome": "made up"`, 1)
	stale = regexp.MustCompile(`"ledger_bytes": \d+`).ReplaceAllString(stale, `"ledger_bytes": 1`)
	if stale == string(raw) {
		t.Fatalf("the summary has an unexpected shape:\n%s", raw)
	}
	if err := os.WriteFile(summary, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	if listStale, findingStale := ask(); listStale != listFast || findingStale != findingFast {
		t.Errorf("an out-of-date summary was trusted:\n%s\nwant\n%s", listStale, listFast)
	}

	// Missing: a run stored before summaries existed.
	if err := os.Remove(summary); err != nil {
		t.Fatal(err)
	}
	if listSlow, findingSlow := ask(); listSlow != listFast || findingSlow != findingFast {
		t.Errorf("list_runs or get_finding differs between the summary and the ledger:\n%s\nwant\n%s", listSlow, listFast)
	}
}

// scan passes since and changed through to the engine, and compare_runs
// returns the comparison of two stored runs.
func TestScanSinceAndCompareRuns(t *testing.T) {
	fx := newFixture(t)
	c := start(t, fx.opts)
	if tr := c.tool("scan", map[string]any{"path": ".", "since": "main"}); tr.IsError {
		t.Logf("scan with since: %s", tr.text())
	}
	if tr := c.tool("scan", map[string]any{"path": ".", "changed": true, "diff_scope": "lines"}); tr.IsError {
		t.Logf("scan with changed: %s", tr.text())
	}
	seen := *fx.seen
	if len(seen) != 2 || seen[0].Since != "main" || seen[0].Changed || seen[0].DiffScope != "" || !seen[1].Changed || seen[1].Since != "" || seen[1].DiffScope != "lines" {
		t.Fatalf("engine options = %+v", seen)
	}
	// diff_scope is checked in the tool's own words too.
	if tr := c.tool("scan", map[string]any{"path": ".", "diff_scope": "lines"}); !tr.IsError || !strings.Contains(tr.text(), "give since or changed") || strings.Contains(tr.text(), "--") {
		t.Fatalf("diff_scope without a diff scan: %s", tr.text())
	}
	if tr := c.tool("scan", map[string]any{"path": ".", "since": "main", "diff_scope": "hunks"}); !tr.IsError || !strings.Contains(tr.text(), `not "hunks"`) {
		t.Fatalf("unknown diff_scope: %s", tr.text())
	}
	// A blank since, and since with changed, are refused in the tool's
	// own argument names before the engine is called.
	if tr := c.tool("scan", map[string]any{"path": ".", "since": "  "}); !tr.IsError || !strings.Contains(tr.text(), "since is empty") {
		t.Fatalf("blank since: %s", tr.text())
	}
	if tr := c.tool("scan", map[string]any{"path": ".", "since": "main", "changed": true}); !tr.IsError || !strings.Contains(tr.text(), "since and changed choose different file sets") || strings.Contains(tr.text(), "--") {
		t.Fatalf("since with changed: %s", tr.text())
	}
	if len(*fx.seen) != 2 {
		t.Fatalf("a refused scan reached the engine: %+v", *fx.seen)
	}
	*fx.seen = nil
	for i := 0; i < 2; i++ {
		if tr := c.tool("scan", map[string]any{"path": "."}); tr.IsError {
			t.Fatal(tr.text())
		}
	}
	tr := c.tool("compare_runs", map[string]any{"older": "latest", "newer": "latest"})
	if tr.IsError {
		t.Fatal(tr.text())
	}
	var cmp struct {
		New          []map[string]any `json:"new"`
		Gone         []map[string]any `json:"gone"`
		StillPresent []map[string]any `json:"still_present"`
	}
	if err := json.Unmarshal(tr.Structured, &cmp); err != nil {
		t.Fatal(err)
	}
	if len(cmp.New) != 0 || len(cmp.Gone) != 0 || len(cmp.StillPresent) == 0 {
		t.Fatalf("a run compared with itself: %+v", cmp)
	}
	c.refused("compare_runs", map[string]any{"older": "latest"}, "older and newer")
	c.refused("compare_runs", map[string]any{"older": "../x", "newer": "latest"}, "path separator")
}
