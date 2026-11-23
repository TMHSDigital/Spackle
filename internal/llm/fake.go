package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// Fake is a scripted provider for tests. It returns queued responses in
// order and records every request it receives, so tests can assert on what
// would have been sent to a real model.
type Fake struct {
	mu sync.Mutex
	// Script is consumed front to back.
	script []Response
	// Handler, when set, is used instead of the script. It gets the request
	// and its index (0-based).
	Handler func(req Request, n int) (Response, error)
	// Requests holds every request received, in order.
	Requests []Request
	// ModelName is reported by Model.
	ModelName string
	// Remote makes Local report false, to test offline refusal.
	Remote bool
}

// NewFake returns a fake that plays the given responses.
func NewFake(script ...Response) *Fake {
	return &Fake{script: script, ModelName: "fake-model"}
}

// Name implements Provider.
func (f *Fake) Name() string { return "fake" }

// Model implements Provider.
func (f *Fake) Model() string { return f.ModelName }

// Local implements Provider.
func (f *Fake) Local() bool { return !f.Remote }

// Complete implements Provider.
func (f *Fake) Complete(_ context.Context, req Request) (Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.Requests)
	f.Requests = append(f.Requests, req)
	// Real providers refuse a conversation that holds tool calls or tool
	// results when the request defines no tools. Fail the same way, so a
	// caller that drops the tool list is caught in tests.
	if len(req.Tools) == 0 {
		for _, m := range req.Messages {
			if len(m.ToolCalls) > 0 || len(m.ToolResults) > 0 {
				return Response{}, fmt.Errorf("fake provider: request %d has tool blocks in its history and defines no tools", n+1)
			}
		}
	}
	if f.Handler != nil {
		return f.Handler(req, n)
	}
	if len(f.script) == 0 {
		return Response{}, fmt.Errorf("fake provider: script exhausted at request %d", n+1)
	}
	resp := f.script[0]
	f.script = f.script[1:]
	if resp.StopReason == "" {
		if len(resp.ToolCalls) > 0 {
			resp.StopReason = StopToolUse
		} else {
			resp.StopReason = StopEnd
		}
	}
	if resp.Usage.InputTokens == 0 && resp.Usage.OutputTokens == 0 {
		resp.Usage = Usage{InputTokens: EstimateRequestTokens(req), OutputTokens: estimateTokens(resp.Text) + 1, Estimated: true}
	}
	return resp, nil
}

// Remaining returns how many scripted responses are left.
func (f *Fake) Remaining() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.script)
}

// Sent returns everything the fake received as one string, for asserting
// that something was or was not sent to the model.
func (f *Fake) Sent() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal(f.Requests)
	return string(b)
}

// Say is a scripted text response.
func Say(text string) Response { return Response{Text: text} }

// Call is a scripted response that calls one tool.
func Call(id, name string, args any) Response {
	raw, err := json.Marshal(args)
	if err != nil {
		panic(err)
	}
	return Response{ToolCalls: []ToolCall{{ID: id, Name: name, Args: raw}}}
}
