package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const openAIDefaultBase = "https://api.openai.com/v1"

// OpenAI speaks the Chat Completions shape. It serves OpenAI itself and any
// compatible endpoint: OpenRouter, Azure OpenAI, Together, Groq, Fireworks,
// llama.cpp, LM Studio, vLLM.
type OpenAI struct {
	kind    string // "openai" or "openai-compatible"
	model   string
	baseURL string
	key     string
	client  *http.Client
}

// NewOpenAI builds the provider. kind is "openai" or "openai-compatible".
// baseURL is the API root that /chat/completions is appended to.
func NewOpenAI(kind, model, baseURL, key string, client *http.Client) *OpenAI {
	if baseURL == "" {
		baseURL = openAIDefaultBase
	}
	return &OpenAI{kind: kind, model: model, baseURL: baseURL, key: key, client: client}
}

// Name implements Provider.
func (o *OpenAI) Name() string { return o.kind }

// Model implements Provider.
func (o *OpenAI) Model() string { return o.model }

// Local implements Provider.
func (o *OpenAI) Local() bool { return IsLoopbackURL(o.baseURL) }

// endpoint joins a path onto the base URL, keeping any query string the
// base carries (Azure puts api-version there).
func (o *OpenAI) endpoint(path string) string {
	u, err := url.Parse(o.baseURL)
	if err != nil {
		return strings.TrimRight(o.baseURL, "/") + path
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String()
}

func (o *OpenAI) isAzure() bool {
	u, err := url.Parse(o.baseURL)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return strings.HasSuffix(h, ".openai.azure.com") || strings.HasSuffix(h, ".cognitiveservices.azure.com")
}

func (o *OpenAI) isOpenRouter() bool { return ReportsCost(o.baseURL) }

// ReportsCost reports whether the endpoint at baseURL returns the cost of
// each request, so spend is known without a price entry. OpenRouter does.
func ReportsCost(baseURL string) bool {
	u, err := url.Parse(baseURL)
	return err == nil && strings.EqualFold(u.Hostname(), "openrouter.ai")
}

func (o *OpenAI) headers() map[string]string {
	h := map[string]string{}
	if o.key == "" {
		return h // local servers usually need no key
	}
	if o.isAzure() {
		h["api-key"] = o.key
	} else {
		h["Authorization"] = "Bearer " + o.key
	}
	return h
}

type oaToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaMessage struct {
	Role       string       `json:"role"`
	Content    *string      `json:"content"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}

type oaTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type oaRequest struct {
	Model    string      `json:"model"`
	Messages []oaMessage `json:"messages"`
	Tools    []oaTool    `json:"tools,omitempty"`
	// OpenAI's current models take max_completion_tokens; most compatible
	// servers still take max_tokens. Exactly one is sent.
	MaxCompletionTokens int `json:"max_completion_tokens,omitempty"`
	MaxTokens           int `json:"max_tokens,omitempty"`
	// Usage asks OpenRouter to include the request's real cost.
	Usage *oaUsageOpt `json:"usage,omitempty"`
}

type oaUsageOpt struct {
	Include bool `json:"include"`
}

type oaResponse struct {
	Choices []struct {
		Message struct {
			Content   *string      `json:"content"`
			Refusal   *string      `json:"refusal"`
			ToolCalls []oaToolCall `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens        int      `json:"prompt_tokens"`
		CompletionTokens    int      `json:"completion_tokens"`
		Cost                *float64 `json:"cost"`
		PromptTokensDetails *struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	} `json:"usage"`
}

func strPtr(s string) *string { return &s }

// Complete implements Provider.
func (o *OpenAI) Complete(ctx context.Context, req Request) (Response, error) {
	body := oaRequest{Model: o.model}
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 16000
	}
	if o.kind == "openai" || o.isAzure() {
		body.MaxCompletionTokens = maxTokens
	} else {
		body.MaxTokens = maxTokens
	}
	if o.isOpenRouter() {
		body.Usage = &oaUsageOpt{Include: true}
	}
	if req.System != "" {
		body.Messages = append(body.Messages, oaMessage{Role: "system", Content: strPtr(req.System)})
	}
	for _, m := range req.Messages {
		switch m.Role {
		case RoleUser:
			body.Messages = append(body.Messages, oaMessage{Role: "user", Content: strPtr(m.Text)})
		case RoleAssistant:
			am := oaMessage{Role: "assistant"}
			if m.Text != "" || len(m.ToolCalls) == 0 {
				am.Content = strPtr(m.Text)
			}
			for _, c := range m.ToolCalls {
				tc := oaToolCall{ID: c.ID, Type: "function"}
				tc.Function.Name = c.Name
				tc.Function.Arguments = string(c.Args)
				if tc.Function.Arguments == "" {
					tc.Function.Arguments = "{}"
				}
				am.ToolCalls = append(am.ToolCalls, tc)
			}
			body.Messages = append(body.Messages, am)
		case RoleTool:
			for _, r := range m.ToolResults {
				content := r.Content
				if r.IsError {
					content = "ERROR: " + content
				}
				if content == "" {
					content = "(no output)"
				}
				body.Messages = append(body.Messages, oaMessage{Role: "tool", Content: strPtr(content), ToolCallID: r.CallID})
			}
		default:
			return Response{}, fmt.Errorf("message role %q is not supported", m.Role)
		}
	}
	for _, t := range req.Tools {
		ot := oaTool{Type: "function"}
		ot.Function.Name = t.Name
		ot.Function.Description = t.Description
		ot.Function.Parameters = t.Schema
		if len(ot.Function.Parameters) == 0 {
			ot.Function.Parameters = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		body.Tools = append(body.Tools, ot)
	}

	var out oaResponse
	if err := doJSON(ctx, o.client, o.kind, http.MethodPost, o.endpoint("/chat/completions"), o.headers(), body, &out); err != nil {
		return Response{}, err
	}
	if len(out.Choices) == 0 {
		return Response{}, fmt.Errorf("%s returned no choices: the endpoint may not implement Chat Completions; check base_url", o.kind)
	}
	choice := out.Choices[0]
	resp := Response{}
	if choice.Message.Content != nil {
		resp.Text = *choice.Message.Content
	}
	for i, tc := range choice.Message.ToolCalls {
		args := json.RawMessage(tc.Function.Arguments)
		if strings.TrimSpace(tc.Function.Arguments) == "" {
			args = json.RawMessage(`{}`)
		}
		id := tc.ID
		if id == "" {
			// Some local servers omit ids. The id only has to pair a call
			// with its result inside this conversation.
			id = fmt.Sprintf("call_%d", i)
		}
		resp.ToolCalls = append(resp.ToolCalls, ToolCall{ID: id, Name: tc.Function.Name, Args: args})
	}
	switch {
	case choice.Message.Refusal != nil && *choice.Message.Refusal != "":
		resp.StopReason, resp.RefusalNote = StopRefusal, *choice.Message.Refusal
		resp.ToolCalls = nil
	case choice.FinishReason == "content_filter":
		resp.StopReason, resp.RefusalNote = StopRefusal, "content filter"
		resp.ToolCalls = nil
	case choice.FinishReason == "length":
		resp.StopReason = StopMaxTokens
		resp.ToolCalls = nil // arguments may be cut off
	case len(resp.ToolCalls) > 0:
		resp.StopReason = StopToolUse
	default:
		resp.StopReason = StopEnd
	}

	if out.Usage != nil && (out.Usage.PromptTokens > 0 || out.Usage.CompletionTokens > 0) {
		resp.Usage = Usage{InputTokens: out.Usage.PromptTokens, OutputTokens: out.Usage.CompletionTokens}
		if d := out.Usage.PromptTokensDetails; d != nil {
			resp.Usage.CachedInputTokens = d.CachedTokens
		}
		if out.Usage.Cost != nil {
			resp.Usage.CostUSD, resp.Usage.CostKnown = *out.Usage.Cost, true
		}
	} else {
		resp.Usage = Usage{InputTokens: EstimateRequestTokens(req), OutputTokens: estimateTokens(resp.Text), Estimated: true}
	}
	return resp, nil
}

// Probe implements Prober. It lists models when the endpoint supports that,
// which is free. Endpoints without a models route (some Azure deployments)
// are reported as unverified rather than failed.
func (o *OpenAI) Probe(ctx context.Context) (string, []string, error) {
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	err := doJSON(ctx, o.client, o.kind, http.MethodGet, o.endpoint("/models"), o.headers(), nil, &out)
	if err != nil {
		var apiErr *APIError
		if asAPIError(err, &apiErr) && (apiErr.Status == 404 || apiErr.Status == 405) {
			return "endpoint has no model list; the model name is not verified until the first call", nil, nil
		}
		return "", nil, err
	}
	for _, m := range out.Data {
		if m.ID == o.model {
			return "model found at " + hostOf(o.baseURL), nil, nil
		}
	}
	if len(out.Data) == 0 {
		return "endpoint answered; it lists no models, so the model name is not verified", nil, nil
	}
	return "", nil, fmt.Errorf("model %q is not in the list returned by %s: check the model name (the endpoint lists %d models)", o.model, hostOf(o.baseURL), len(out.Data))
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}
