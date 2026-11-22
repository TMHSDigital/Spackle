package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const ollamaDefaultBase = "http://127.0.0.1:11434"

// Ollama speaks Ollama's native chat API.
type Ollama struct {
	model   string
	baseURL string
	client  *http.Client
}

// NewOllama builds the provider. baseURL may be empty for the local default.
func NewOllama(model, baseURL string, client *http.Client) *Ollama {
	if baseURL == "" {
		baseURL = ollamaDefaultBase
	}
	return &Ollama{model: model, baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

// Name implements Provider.
func (o *Ollama) Name() string { return "ollama" }

// Model implements Provider.
func (o *Ollama) Model() string { return o.model }

// Local implements Provider.
func (o *Ollama) Local() bool { return IsLoopbackURL(o.baseURL) }

type olToolCall struct {
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

type olMessage struct {
	Role      string       `json:"role"`
	Content   string       `json:"content"`
	ToolCalls []olToolCall `json:"tool_calls,omitempty"`
	ToolName  string       `json:"tool_name,omitempty"`
}

type olRequest struct {
	Model    string         `json:"model"`
	Messages []olMessage    `json:"messages"`
	Tools    []oaTool       `json:"tools,omitempty"`
	Stream   bool           `json:"stream"`
	Options  map[string]any `json:"options,omitempty"`
}

type olResponse struct {
	Message         olMessage `json:"message"`
	DoneReason      string    `json:"done_reason"`
	PromptEvalCount int       `json:"prompt_eval_count"`
	EvalCount       int       `json:"eval_count"`
}

// Complete implements Provider.
func (o *Ollama) Complete(ctx context.Context, req Request) (Response, error) {
	body := olRequest{Model: o.model, Stream: false}
	if req.MaxTokens > 0 {
		body.Options = map[string]any{"num_predict": req.MaxTokens}
	}
	if req.System != "" {
		body.Messages = append(body.Messages, olMessage{Role: "system", Content: req.System})
	}
	for _, m := range req.Messages {
		switch m.Role {
		case RoleUser:
			body.Messages = append(body.Messages, olMessage{Role: "user", Content: m.Text})
		case RoleAssistant:
			am := olMessage{Role: "assistant", Content: m.Text}
			for _, c := range m.ToolCalls {
				var tc olToolCall
				tc.Function.Name = c.Name
				tc.Function.Arguments = c.Args
				if len(tc.Function.Arguments) == 0 {
					tc.Function.Arguments = json.RawMessage(`{}`)
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
				body.Messages = append(body.Messages, olMessage{Role: "tool", Content: content, ToolName: r.Name})
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

	var out olResponse
	if err := doJSON(ctx, o.client, "ollama", http.MethodPost, o.baseURL+"/api/chat", nil, body, &out); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == 400 && strings.Contains(apiErr.Message, "does not support tools") {
			return Response{}, fmt.Errorf("ollama model %s does not support tool calling, which Spackle's agents need: choose a tool-capable model (run \"spackle doctor\" to check)", o.model)
		}
		return Response{}, err
	}
	resp := Response{Text: out.Message.Content}
	for i, tc := range out.Message.ToolCalls {
		args := tc.Function.Arguments
		if len(args) == 0 {
			args = json.RawMessage(`{}`)
		}
		// Ollama gives calls no id; results are matched by tool name.
		resp.ToolCalls = append(resp.ToolCalls, ToolCall{ID: fmt.Sprintf("call_%d", i), Name: tc.Function.Name, Args: args})
	}
	switch {
	case out.DoneReason == "length":
		resp.StopReason = StopMaxTokens
		resp.ToolCalls = nil
	case len(resp.ToolCalls) > 0:
		resp.StopReason = StopToolUse
	default:
		resp.StopReason = StopEnd
	}
	if out.PromptEvalCount > 0 || out.EvalCount > 0 {
		resp.Usage = Usage{InputTokens: out.PromptEvalCount, OutputTokens: out.EvalCount}
	} else {
		resp.Usage = Usage{InputTokens: EstimateRequestTokens(req), OutputTokens: estimateTokens(resp.Text), Estimated: true}
	}
	return resp, nil
}

var paramSizeRe = regexp.MustCompile(`(?i)^\s*([0-9]+(?:\.[0-9]+)?)\s*([MB])`)

// minUsefulParamsB is the size, in billions of parameters, below which a
// local model is unlikely to drive the investigation loop well. It is a
// warning threshold, not a limit.
const minUsefulParamsB = 20.0

// Probe implements Prober. It asks Ollama about the model and warns when it
// lacks tool calling or looks too small for agentic work.
func (o *Ollama) Probe(ctx context.Context) (string, []string, error) {
	var out struct {
		Capabilities []string `json:"capabilities"`
		Details      struct {
			ParameterSize     string `json:"parameter_size"`
			QuantizationLevel string `json:"quantization_level"`
		} `json:"details"`
	}
	err := doJSON(ctx, o.client, "ollama", http.MethodPost, o.baseURL+"/api/show", nil, map[string]string{"model": o.model}, &out)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == 404 {
			return "", nil, fmt.Errorf("ollama has no model %q: pull it with \"ollama pull %s\" or fix the model name", o.model, o.model)
		}
		return "", nil, fmt.Errorf("%w. Is Ollama running at %s?", err, o.baseURL)
	}
	var warnings []string
	note := strings.TrimSpace(out.Details.ParameterSize + " " + out.Details.QuantizationLevel)
	if len(out.Capabilities) > 0 {
		hasTools := false
		for _, c := range out.Capabilities {
			if c == "tools" {
				hasTools = true
			}
		}
		if !hasTools {
			warnings = append(warnings, "this model does not report tool calling; investigators, the prover and the fixer need it")
		}
	}
	if m := paramSizeRe.FindStringSubmatch(out.Details.ParameterSize); m != nil {
		size, _ := strconv.ParseFloat(m[1], 64)
		if strings.EqualFold(m[2], "M") {
			size /= 1000
		}
		if size < minUsefulParamsB {
			warnings = append(warnings, fmt.Sprintf("%s parameters is small for agentic security work; expect missed findings and malformed tool calls. A strong coding model in a larger size class does better", out.Details.ParameterSize))
		}
	}
	return note, warnings, nil
}

// asAPIError is errors.As for *APIError, shared by the providers.
func asAPIError(err error, target **APIError) bool { return errors.As(err, target) }
