package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	anthropicDefaultBase = "https://api.anthropic.com"
	// anthropicVersion is the API version header. Spackle sends none of the
	// parameters later versions removed (sampling, thinking budgets, forced
	// tool choice), so requests are valid across current models.
	anthropicVersion = "2023-06-01"
)

// Anthropic speaks the native Messages API.
type Anthropic struct {
	model   string
	baseURL string
	key     string
	client  *http.Client
}

// NewAnthropic builds the provider. baseURL may be empty for the public API.
func NewAnthropic(model, baseURL, key string, client *http.Client) *Anthropic {
	if baseURL == "" {
		baseURL = anthropicDefaultBase
	}
	return &Anthropic{model: model, baseURL: strings.TrimRight(baseURL, "/"), key: key, client: client}
}

// Name implements Provider.
func (a *Anthropic) Name() string { return "anthropic" }

// Model implements Provider.
func (a *Anthropic) Model() string { return a.model }

// Local implements Provider.
func (a *Anthropic) Local() bool { return IsLoopbackURL(a.baseURL) }

func (a *Anthropic) headers() map[string]string {
	return map[string]string{"x-api-key": a.key, "anthropic-version": anthropicVersion}
}

type anthBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

type anthMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type anthTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type anthRequest struct {
	Model     string        `json:"model"`
	MaxTokens int           `json:"max_tokens"`
	System    string        `json:"system,omitempty"`
	Messages  []anthMessage `json:"messages"`
	Tools     []anthTool    `json:"tools,omitempty"`
	// CacheControl at the top level lets the API place the cache breakpoint
	// on the last cacheable block. An agent loop resends a growing prefix
	// every turn, so this cuts input cost substantially.
	CacheControl *anthCache `json:"cache_control,omitempty"`
}

type anthCache struct {
	Type string `json:"type"`
}

type anthResponse struct {
	Content     []json.RawMessage `json:"content"`
	StopReason  string            `json:"stop_reason"`
	StopDetails *struct {
		Category    string `json:"category"`
		Explanation string `json:"explanation"`
	} `json:"stop_details"`
	Usage struct {
		InputTokens              int `json:"input_tokens"`
		OutputTokens             int `json:"output_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	} `json:"usage"`
}

// Complete implements Provider.
//
// Notes on the request shape, for current Claude models:
//   - No thinking parameter is sent. Thinking is adaptive by default, and
//     explicit budgets or "disabled" are rejected by several models.
//   - No temperature, top_p or top_k: they are rejected too.
//   - tool_choice is left at its default (auto). Forcing a tool is rejected.
//   - Earlier assistant turns are replayed byte for byte from Message.Raw,
//     because thinking blocks are bound to the conversation that made them.
func (a *Anthropic) Complete(ctx context.Context, req Request) (Response, error) {
	body := anthRequest{Model: a.model, MaxTokens: req.MaxTokens, System: req.System, CacheControl: &anthCache{Type: "ephemeral"}}
	if body.MaxTokens <= 0 {
		body.MaxTokens = 16000
	}
	for _, t := range req.Tools {
		schema := t.Schema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		body.Tools = append(body.Tools, anthTool{Name: t.Name, Description: t.Description, InputSchema: schema})
	}
	for _, m := range req.Messages {
		am, err := toAnthropic(m)
		if err != nil {
			return Response{}, err
		}
		// The API requires alternating roles; tool results are user turns,
		// so merge them into a preceding user turn if there is one.
		body.Messages = append(body.Messages, am)
	}

	var out anthResponse
	if err := doJSON(ctx, a.client, "anthropic", http.MethodPost, a.baseURL+"/v1/messages", a.headers(), body, &out); err != nil {
		return Response{}, err
	}

	resp := Response{}
	for _, raw := range out.Content {
		var b anthBlock
		if err := json.Unmarshal(raw, &b); err != nil {
			continue
		}
		switch b.Type {
		case "text":
			resp.Text += b.Text
		case "tool_use":
			args := b.Input
			if len(args) == 0 {
				args = json.RawMessage(`{}`)
			}
			resp.ToolCalls = append(resp.ToolCalls, ToolCall{ID: b.ID, Name: b.Name, Args: args})
		}
	}
	rawContent, err := json.Marshal(out.Content)
	if err != nil {
		return Response{}, fmt.Errorf("re-encode anthropic content: %w", err)
	}
	resp.Raw = rawContent

	switch out.StopReason {
	case "tool_use":
		resp.StopReason = StopToolUse
	case "max_tokens", "model_context_window_exceeded":
		resp.StopReason = StopMaxTokens
	case "refusal":
		resp.StopReason = StopRefusal
		if out.StopDetails != nil {
			resp.RefusalNote = strings.TrimSpace(out.StopDetails.Category + " " + out.StopDetails.Explanation)
		}
	default:
		resp.StopReason = StopEnd
	}
	// A tool call cut off by max_tokens has incomplete arguments. Do not
	// hand it to the tool runner.
	if resp.StopReason != StopToolUse {
		resp.ToolCalls = nil
	}

	u := out.Usage
	resp.Usage = Usage{
		InputTokens:       u.InputTokens + u.CacheCreationInputTokens + u.CacheReadInputTokens,
		OutputTokens:      u.OutputTokens,
		CachedInputTokens: u.CacheReadInputTokens,
		CacheWriteTokens:  u.CacheCreationInputTokens,
	}
	if resp.Usage.InputTokens == 0 && resp.Usage.OutputTokens == 0 {
		resp.Usage = Usage{InputTokens: EstimateRequestTokens(req), OutputTokens: estimateTokens(resp.Text), Estimated: true}
	}
	return resp, nil
}

func toAnthropic(m Message) (anthMessage, error) {
	switch m.Role {
	case RoleAssistant:
		if len(m.Raw) > 0 {
			return anthMessage{Role: "assistant", Content: m.Raw}, nil
		}
		var blocks []anthBlock
		if m.Text != "" {
			blocks = append(blocks, anthBlock{Type: "text", Text: m.Text})
		}
		for _, c := range m.ToolCalls {
			args := c.Args
			if len(args) == 0 {
				args = json.RawMessage(`{}`)
			}
			blocks = append(blocks, anthBlock{Type: "tool_use", ID: c.ID, Name: c.Name, Input: args})
		}
		return encodeAnth("assistant", blocks)
	case RoleTool:
		// All results for one assistant turn go back in a single user
		// message; splitting them teaches the model to stop calling tools
		// in parallel.
		blocks := make([]anthBlock, 0, len(m.ToolResults))
		for _, r := range m.ToolResults {
			content := r.Content
			if content == "" {
				content = "(no output)"
			}
			blocks = append(blocks, anthBlock{Type: "tool_result", ToolUseID: r.CallID, Content: content, IsError: r.IsError})
		}
		return encodeAnth("user", blocks)
	case RoleUser:
		return encodeAnth("user", []anthBlock{{Type: "text", Text: m.Text}})
	}
	return anthMessage{}, fmt.Errorf("message role %q is not supported", m.Role)
}

func encodeAnth(role string, blocks []anthBlock) (anthMessage, error) {
	raw, err := json.Marshal(blocks)
	if err != nil {
		return anthMessage{}, err
	}
	return anthMessage{Role: role, Content: raw}, nil
}

// Probe implements Prober with the Models API, which validates the key and
// the model name without spending tokens.
func (a *Anthropic) Probe(ctx context.Context) (string, []string, error) {
	var out struct {
		ID             string `json:"id"`
		DisplayName    string `json:"display_name"`
		MaxInputTokens int    `json:"max_input_tokens"`
	}
	endpoint := a.baseURL + "/v1/models/" + url.PathEscape(a.model)
	if err := doJSON(ctx, a.client, "anthropic", http.MethodGet, endpoint, a.headers(), nil, &out); err != nil {
		return "", nil, err
	}
	note := out.DisplayName
	if note == "" {
		note = out.ID
	}
	if out.MaxInputTokens > 0 {
		note += fmt.Sprintf(", %d token context", out.MaxInputTokens)
	}
	return note, nil, nil
}
