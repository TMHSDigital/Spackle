package llm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/redact"
)

// Redacting wraps a provider so that no secret value can reach it. Every
// piece of outbound text (system prompt, user text, tool results, tool call
// arguments being replayed) passes through secret detection first.
//
// This is the last line of defense, not the only one: tools redact their
// own output too. It exists so that a new tool or prompt that forgets to
// redact still cannot leak.
type Redacting struct {
	inner Provider
	mu    sync.Mutex
	hits  int
}

// NewRedacting wraps p.
func NewRedacting(p Provider) *Redacting { return &Redacting{inner: p} }

// Name implements Provider.
func (r *Redacting) Name() string { return r.inner.Name() }

// Model implements Provider.
func (r *Redacting) Model() string { return r.inner.Model() }

// Local implements Provider.
func (r *Redacting) Local() bool { return r.inner.Local() }

// Unwrap returns the wrapped provider.
func (r *Redacting) Unwrap() Provider { return r.inner }

// Redactions returns how many secrets have been removed so far.
func (r *Redacting) Redactions() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits
}

func (r *Redacting) clean(s string) string {
	if s == "" {
		return s
	}
	out, matches := redact.Apply(s)
	if len(matches) > 0 {
		r.mu.Lock()
		r.hits += len(matches)
		r.mu.Unlock()
	}
	return out
}

// Complete implements Provider.
func (r *Redacting) Complete(ctx context.Context, req Request) (Response, error) {
	clean := Request{System: r.clean(req.System), MaxTokens: req.MaxTokens, Tools: req.Tools}
	clean.Messages = make([]Message, len(req.Messages))
	for i, m := range req.Messages {
		cm := Message{Role: m.Role, Text: r.clean(m.Text), Raw: m.Raw}
		for _, c := range m.ToolCalls {
			cm.ToolCalls = append(cm.ToolCalls, ToolCall{ID: c.ID, Name: c.Name, Args: []byte(r.clean(string(c.Args)))})
		}
		for _, tr := range m.ToolResults {
			cm.ToolResults = append(cm.ToolResults, ToolResult{CallID: tr.CallID, Name: tr.Name, Content: r.clean(tr.Content), IsError: tr.IsError})
		}
		// Raw is the provider's own earlier output. It was produced from
		// already-redacted input, but check it anyway: if a secret is found
		// drop Raw so the turn is rebuilt from the cleaned fields.
		if len(m.Raw) > 0 && len(redact.Scan(string(m.Raw))) > 0 {
			cm.Raw = nil
		}
		clean.Messages[i] = cm
	}
	return r.inner.Complete(ctx, clean)
}

// Probe forwards to the wrapped provider when it supports probing.
func (r *Redacting) Probe(ctx context.Context) (string, []string, error) {
	if p, ok := r.inner.(Prober); ok {
		return p.Probe(ctx)
	}
	return "", nil, nil
}

// Options control provider construction.
type Options struct {
	Offline bool
	// Getenv reads environment variables; nil means os.Getenv.
	Getenv func(string) string
}

// New builds the provider for a model config, wrapped with redaction. In
// offline mode it fails before any request is made if the endpoint is not on
// this machine, and the HTTP client it uses refuses non-loopback addresses.
func New(m config.Model, opts Options) (Provider, error) {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	if !m.Configured() {
		return nil, errors.New("no model provider is configured: set [model] in spackle.toml or pass --provider and --model")
	}
	keyEnv := m.APIKeyEnv
	if keyEnv == "" {
		keyEnv = config.DefaultKeyEnv(m.Provider)
	}
	key := ""
	if keyEnv != "" {
		key = strings.TrimSpace(getenv(keyEnv))
	}
	client := NewHTTPClient(opts.Offline)

	var p Provider
	switch m.Provider {
	case config.ProviderAnthropic:
		if key == "" {
			return nil, fmt.Errorf("environment variable %s is not set: the Anthropic provider needs an API key from the Anthropic console. A claude.ai subscription is not API access", keyEnv)
		}
		p = NewAnthropic(m.Model, m.BaseURL, key, client)
	case config.ProviderOpenAI:
		if key == "" {
			return nil, fmt.Errorf("environment variable %s is not set: the OpenAI provider needs an API key", keyEnv)
		}
		p = NewOpenAI("openai", m.Model, m.BaseURL, key, client)
	case config.ProviderOpenAICompatible:
		if m.BaseURL == "" {
			return nil, errors.New("provider openai-compatible needs --base-url or base_url (for example https://openrouter.ai/api/v1)")
		}
		// A key is required for remote endpoints and optional for local
		// servers, which usually accept any or none.
		if key == "" && !IsLoopbackURL(m.BaseURL) {
			return nil, fmt.Errorf("environment variable %s is not set: %s needs an API key. Set the variable, or name another one with api_key_env", keyEnv, hostOf(m.BaseURL))
		}
		p = NewOpenAI("openai-compatible", m.Model, m.BaseURL, key, client)
	case config.ProviderOllama:
		p = NewOllama(m.Model, m.BaseURL, client)
	default:
		return nil, fmt.Errorf("unknown provider %q: use anthropic, openai, openai-compatible or ollama", m.Provider)
	}

	if opts.Offline && !p.Local() {
		return nil, fmt.Errorf("%w: provider %s would send requests to another machine. Use ollama or an openai-compatible server on localhost, or drop --offline", ErrOffline, m.Provider)
	}
	return NewRedacting(p), nil
}

// PricesFromConfig converts config pricing into llm prices.
func PricesFromConfig(in map[string]config.Price) map[string]Price {
	out := make(map[string]Price, len(in))
	for model, p := range in {
		out[model] = Price{Input: p.InputPerMTok, Output: p.OutputPerMTok}
	}
	return out
}
