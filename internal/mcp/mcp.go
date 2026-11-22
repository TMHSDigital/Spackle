// Package mcp serves Spackle to AI clients over the Model Context Protocol:
// JSON-RPC 2.0 messages, one per line, read from one stream and written to
// another (the stdio transport). It offers tools and nothing else, and it
// never opens a listener.
//
// The protocol layer is written by hand on the standard library because the
// server needs only initialize, ping, tools/list and tools/call, and a
// dependency would have to be justified for four methods.
//
// The safety model is that the operator who starts the server sets every
// limit (which directories may be scanned, whether a model may be called,
// the config and its budgets) and a tool call can only choose within them.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/engine"
)

// ProtocolVersion is the newest MCP revision the server speaks. It is also
// the answer to a client that asks for a revision the server does not know.
const ProtocolVersion = "2025-06-18"

// supportedVersions lists the revisions a client may ask for. The tools
// subset this server uses is the same in all of them.
var supportedVersions = []string{ProtocolVersion, "2025-03-26", "2024-11-05"}

// maxMessage caps one incoming line so a client cannot make the server hold
// an unbounded message in memory.
const maxMessage = 16 << 20

// maxPendingCalls caps the tool calls that are running or waiting. Each one
// holds its arguments in memory, so the queue must not grow without limit.
// Other requests are not counted, so ping still answers when it is full.
const maxPendingCalls = 8

// JSON-RPC 2.0 error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
)

// ErrOptions marks a Serve failure caused by the options the operator gave
// (for example a root that is not a directory), so the CLI can report it as
// a usage error.
var ErrOptions = errors.New("invalid MCP server options")

// Check is one row of the doctor tool's output.
type Check struct {
	Area   string `json:"area"`
	Name   string `json:"name"`
	Status string `json:"status"` // ok|missing|warn|fail
	Note   string `json:"note"`
}

// Options configure the server. Everything here comes from the operator's
// command line and config file; nothing in it can be changed by a tool call.
type Options struct {
	// Roots are the only directories the scan tool may be pointed at. Empty
	// means the working directory.
	Roots []string
	// Config is the operator's configuration, with flags already applied.
	Config config.Config
	// AllowModel lets scans call the configured model. Without it scans run
	// the deterministic stages only, so a client cannot spend the operator's
	// money.
	AllowModel bool
	// Version is reported to the client as the server version.
	Version string
	// Doctor runs the environment checks for the doctor tool. It is passed
	// in because the checks live in the CLI package, which imports this one.
	Doctor func(ctx context.Context) []Check
	// Log receives status lines (stderr). Nil discards them. Standard output
	// is never used for status: it carries protocol messages only.
	Log io.Writer
	// Scan runs a scan; nil means engine.Run. Tests inject a fake.
	Scan func(ctx context.Context, opts engine.Options) (engine.Result, error)
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// session is the state of one Serve call.
type session struct {
	srv *server

	writeMu sync.Mutex
	out     io.Writer
	// stop ends the session. A failed write calls it: the client has gone,
	// and finishing a scan for nobody would waste the operator's machine.
	stop context.CancelFunc

	// slot is held by the one tool call that is running. Calls never overlap,
	// so a client cannot multiply load or spend by calling in parallel.
	slot chan struct{}
	// pending counts tool calls that are running or waiting for the slot.
	pending chan struct{}

	mu       sync.Mutex
	inFlight map[string]context.CancelFunc // requests being answered, by id

	wg sync.WaitGroup
}

// Serve answers MCP requests read from in, writing replies to out, until in
// ends or ctx is cancelled. It returns nil when in reaches EOF, after every
// request already read has been answered. Requests are answered concurrently
// except tool calls, which run one at a time.
func Serve(ctx context.Context, in io.Reader, out io.Writer, opts Options) error {
	srv, err := newServer(opts)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ss := &session{
		srv: srv, out: out, stop: cancel,
		slot:     make(chan struct{}, 1),
		pending:  make(chan struct{}, maxPendingCalls),
		inFlight: map[string]context.CancelFunc{},
	}
	// A client may send its requests and close standard input at once; the
	// replies it is still owed are written before Serve returns.
	defer ss.wg.Wait()

	srv.logf("spackle mcp: serving on standard input and output. Scan roots: %q. Model calls: %s.", srv.roots, srv.modelMode())

	type message struct {
		data    []byte
		tooLong bool
	}
	msgs := make(chan message)
	readErr := make(chan error, 1)
	go func() {
		defer close(msgs)
		br := bufio.NewReaderSize(in, 64<<10)
		for {
			data, tooLong, err := readLine(br)
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				readErr <- err
				return
			}
			select {
			case msgs <- message{data, tooLong}:
			case <-ctx.Done():
				readErr <- nil
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case m, ok := <-msgs:
			if !ok {
				if err := <-readErr; err != nil {
					return fmt.Errorf("read MCP input: %w", err)
				}
				return nil
			}
			if m.tooLong {
				// The oversized line was consumed to its end, so the session
				// stays usable and the next message still parses.
				ss.reply(nil, nil, &rpcError{codeParse, fmt.Sprintf("message too large: one message may be at most %d bytes", maxMessage)})
				continue
			}
			ss.dispatch(ctx, m.data)
		}
	}
}

// readLine returns the next newline-terminated line. A line over maxMessage
// is read through to its newline and reported as too long with no data, so
// the bytes are never held. A final line without a newline is returned
// before io.EOF.
func readLine(br *bufio.Reader) (data []byte, tooLong bool, err error) {
	for {
		chunk, rerr := br.ReadSlice('\n')
		if !tooLong {
			if len(data)+len(chunk) > maxMessage+1 { // the newline is not counted
				data, tooLong = nil, true
			} else {
				data = append(data, chunk...)
			}
		}
		switch {
		case rerr == nil:
			return data, tooLong, nil
		case errors.Is(rerr, bufio.ErrBufferFull):
			continue
		case errors.Is(rerr, io.EOF) && (len(data) > 0 || tooLong):
			return data, tooLong, nil
		default:
			return nil, false, rerr
		}
	}
}

// dispatch parses one line and starts answering it.
func (ss *session) dispatch(ctx context.Context, line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}
	if line[0] == '[' {
		ss.reply(nil, nil, &rpcError{codeInvalidRequest, "batch requests are not supported: send one request per line"})
		return
	}
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		ss.reply(nil, nil, &rpcError{codeParse, "parse error: " + err.Error()})
		return
	}
	isNotification := len(req.ID) == 0
	if req.JSONRPC != "2.0" || req.Method == "" {
		// A malformed notification still gets no reply: the sender is not
		// waiting for one.
		if !isNotification {
			ss.reply(req.ID, nil, &rpcError{codeInvalidRequest, `invalid request: it needs "jsonrpc": "2.0" and a "method"`})
		}
		return
	}
	if isNotification {
		ss.notification(req)
		return
	}

	key := string(req.ID)
	isCall := req.Method == "tools/call"
	ss.mu.Lock()
	if _, dup := ss.inFlight[key]; dup {
		ss.mu.Unlock()
		// A second request under a live id would make the first impossible
		// to cancel by id.
		ss.reply(req.ID, nil, &rpcError{codeInvalidRequest, "a request with this id is still in progress: wait for its reply or use a new id"})
		return
	}
	if isCall {
		select {
		case ss.pending <- struct{}{}:
		default:
			ss.mu.Unlock()
			ss.reply(req.ID, nil, &rpcError{codeInvalidRequest, fmt.Sprintf("too many tool calls pending: at most %d may be running or waiting; retry when one finishes", maxPendingCalls)})
			return
		}
	}
	rctx, cancel := context.WithCancel(ctx)
	ss.inFlight[key] = cancel
	ss.mu.Unlock()

	ss.wg.Go(func() {
		defer func() {
			if isCall {
				<-ss.pending
			}
			ss.mu.Lock()
			delete(ss.inFlight, key)
			ss.mu.Unlock()
			cancel()
		}()
		result, rerr := ss.handle(rctx, req)
		ss.reply(req.ID, result, rerr)
	})
}

// notification handles a message that must not be answered. Only
// cancellation needs any action.
func (ss *session) notification(req request) {
	if req.Method != "notifications/cancelled" {
		return
	}
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil || len(p.RequestID) == 0 {
		return
	}
	ss.mu.Lock()
	cancel := ss.inFlight[string(p.RequestID)]
	ss.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (ss *session) handle(ctx context.Context, req request) (result any, rerr *rpcError) {
	// A panic in a handler must not take down the session or leave the
	// client waiting, so it becomes an internal error reply.
	defer func() {
		if r := recover(); r != nil {
			ss.srv.logf("spackle mcp: internal error in %s: %v", req.Method, r)
			result, rerr = nil, &rpcError{codeInternal, "internal error: the request could not be completed. Run \"spackle doctor\" and report this if it repeats"}
		}
	}()
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		// Params are optional in practice; a client that sends none, or a
		// revision the server does not know, is offered the preferred one.
		_ = json.Unmarshal(req.Params, &p)
		version := ProtocolVersion
		if slices.Contains(supportedVersions, p.ProtocolVersion) {
			version = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "spackle", "version": ss.srv.version},
			"instructions":    instructions,
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": ss.srv.tools}, nil
	case "tools/call":
		return ss.call(ctx, req.Params)
	}
	return nil, &rpcError{codeMethodNotFound, "method not found: " + req.Method}
}

// call runs one tool. Protocol mistakes (bad params, a tool that does not
// exist) are JSON-RPC errors; everything a tool itself refuses or fails at
// is a result with isError set, so the client model can read the reason.
func (ss *session) call(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{codeInvalidParams, "invalid tools/call params: " + err.Error()}
	}
	i := slices.IndexFunc(ss.srv.tools, func(t tool) bool { return t.Name == p.Name })
	if i < 0 {
		return nil, &rpcError{codeInvalidParams, fmt.Sprintf("unknown tool %q: call tools/list for the tools this server offers", p.Name)}
	}
	if len(p.Arguments) == 0 || string(p.Arguments) == "null" {
		p.Arguments = json.RawMessage("{}")
	}
	select {
	case ss.slot <- struct{}{}:
	case <-ctx.Done():
		return toolResult(errorf("cancelled before the call started")), nil
	}
	defer func() { <-ss.slot }()
	ss.srv.logf("spackle mcp: tool call %s", p.Name)
	return toolResult(ss.srv.tools[i].call(ctx, p.Arguments)), nil
}

func toolResult(r result) map[string]any {
	m := map[string]any{
		"content": []map[string]any{{"type": "text", "text": r.text}},
		"isError": r.isError,
	}
	if r.structured != nil {
		m["structuredContent"] = r.structured
	}
	return m
}

func (ss *session) reply(id json.RawMessage, result any, rerr *rpcError) {
	if id == nil {
		id = json.RawMessage("null")
	}
	b, err := json.Marshal(response{JSONRPC: "2.0", ID: id, Result: result, Error: rerr})
	if err != nil {
		b, _ = json.Marshal(response{JSONRPC: "2.0", ID: id, Error: &rpcError{codeInternal, "internal error: the reply could not be encoded: " + err.Error()}})
	}
	ss.writeMu.Lock()
	defer ss.writeMu.Unlock()
	if _, err := ss.out.Write(append(b, '\n')); err != nil {
		ss.stop()
	}
}
