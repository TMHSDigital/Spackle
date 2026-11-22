// Package llm is Spackle's model provider layer: one small interface, three
// wire implementations (Anthropic Messages, OpenAI-compatible Chat
// Completions, Ollama), a scripted fake for tests, and the wrappers that
// enforce redaction and the offline guarantee.
//
// The providers speak HTTP directly through net/http. No vendor SDK is
// linked: Spackle needs one endpoint per provider, and every dependency of a
// security tool is attack surface that has to be audited and kept patched.
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// Roles of a message.
const (
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
)

// Message is one turn in provider-neutral form.
type Message struct {
	Role string
	// Text is the user text, or the assistant's visible text.
	Text string
	// ToolCalls are the calls an assistant turn made.
	ToolCalls []ToolCall
	// ToolResults answer the previous assistant turn's calls (Role tool).
	ToolResults []ToolResult
	// Raw is the provider's own encoding of an assistant turn. Providers
	// that require earlier turns to be replayed exactly (Anthropic's
	// thinking blocks are bound to the conversation) send it back verbatim.
	Raw json.RawMessage
}

// ToolCall is a request from the model to run a tool.
type ToolCall struct {
	ID   string
	Name string
	Args json.RawMessage
}

// ToolResult is the outcome of one tool call.
type ToolResult struct {
	CallID  string
	Name    string
	Content string
	IsError bool
}

// ToolDef describes a tool to the model.
type ToolDef struct {
	Name        string
	Description string
	// Schema is a JSON Schema object for the arguments.
	Schema json.RawMessage
}

// Request is one completion request.
type Request struct {
	System    string
	Messages  []Message
	Tools     []ToolDef
	MaxTokens int
}

// Stop reasons, normalized across providers.
const (
	StopEnd       = "end"        // the model finished its turn
	StopToolUse   = "tool_use"   // the model wants tool results
	StopMaxTokens = "max_tokens" // output was cut off
	StopRefusal   = "refusal"    // the provider declined the request
)

// Response is one completion.
type Response struct {
	Text       string
	ToolCalls  []ToolCall
	StopReason string
	// RefusalNote carries the provider's explanation when StopReason is
	// StopRefusal.
	RefusalNote string
	Usage       Usage
	// Raw is the assistant turn in the provider's own encoding; copy it to
	// Message.Raw when appending the turn to the conversation.
	Raw json.RawMessage
}

// AssistantMessage converts the response into the message to append to the
// conversation.
func (r Response) AssistantMessage() Message {
	return Message{Role: RoleAssistant, Text: r.Text, ToolCalls: r.ToolCalls, Raw: r.Raw}
}

// Usage is token and cost accounting for one call, normalized so budgets
// work the same whichever provider served it.
type Usage struct {
	// InputTokens counts every input token, including cached ones.
	InputTokens  int
	OutputTokens int
	// CachedInputTokens is the part of InputTokens read from a prompt cache.
	CachedInputTokens int
	// CacheWriteTokens is the part of InputTokens written to a prompt cache.
	CacheWriteTokens int
	// Estimated is true when the provider reported no usage and the counts
	// were estimated from byte lengths.
	Estimated bool
	CostUSD   float64
	// CostKnown is false when the model has no known price. CostUSD is then
	// zero and a USD budget cannot be enforced for the call.
	CostKnown bool
}

// Provider is a model backend.
type Provider interface {
	// Name is the provider kind: anthropic, openai, openai-compatible, ollama, fake.
	Name() string
	// Model is the model name requests are sent to.
	Model() string
	// Local reports whether the provider's endpoint is on this machine.
	Local() bool
	Complete(ctx context.Context, req Request) (Response, error)
}

// Prober is implemented by providers that can validate their configuration
// with a request that costs nothing or close to it.
type Prober interface {
	// Probe checks credentials and that the model exists. The note is a
	// short human-readable detail; warnings list concerns that do not block
	// a run (a small local model, no tool-calling support).
	Probe(ctx context.Context) (note string, warnings []string, err error)
}

// APIError is a non-2xx response from a provider.
type APIError struct {
	Provider string
	Status   int
	Message  string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s returned HTTP %d: %s", e.Provider, e.Status, e.Message)
}

// Retryable reports whether the request may succeed if sent again.
func (e *APIError) Retryable() bool {
	return e.Status == 408 || e.Status == 409 || e.Status == 429 || e.Status >= 500
}

// Hint returns what the operator should do about the error.
func (e *APIError) Hint() string {
	switch {
	case e.Status == 401 || e.Status == 403:
		return "the API key was rejected: check the environment variable named by api_key_env"
	case e.Status == 404:
		return "the model or endpoint was not found: check the model name and base_url"
	case e.Status == 429:
		return "rate limited or out of credit: wait, lower concurrency, or check the account balance"
	case e.Status == 400:
		return "the provider rejected the request: the model may not support tool calling"
	case e.Status >= 500:
		return "the provider had an internal error: retry later"
	}
	return ""
}

// ErrOffline is returned when a call would leave the machine in offline mode.
var ErrOffline = errors.New("offline mode: refusing a connection that would leave this machine")

// estimateTokens approximates a token count from text length. Four bytes per
// token is the usual rule of thumb for English and code; the result is only
// used when a provider reports no usage, and is marked Estimated.
func estimateTokens(s string) int {
	if s == "" {
		return 0
	}
	return (len(s) + 3) / 4
}

// requestSize returns the approximate text size of a request, for estimates.
func requestSize(req Request) int {
	n := len(req.System)
	for _, m := range req.Messages {
		n += len(m.Text)
		for _, c := range m.ToolCalls {
			n += len(c.Name) + len(c.Args)
		}
		for _, r := range m.ToolResults {
			n += len(r.Content)
		}
	}
	for _, t := range req.Tools {
		n += len(t.Name) + len(t.Description) + len(t.Schema)
	}
	return n
}

// EstimateRequestTokens approximates the input tokens of a request.
func EstimateRequestTokens(req Request) int { return (requestSize(req) + 3) / 4 }
