package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TMHSDigital/spackle/internal/config"
)

// capture is a test server that records the last request and replies with a
// fixed body.
type capture struct {
	srv     *httptest.Server
	path    string
	headers http.Header
	body    map[string]any
	calls   atomic.Int32
}

func serve(t *testing.T, status int, reply string) *capture {
	t.Helper()
	c := &capture{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.calls.Add(1)
		c.path = r.URL.RequestURI()
		c.headers = r.Header.Clone()
		raw, _ := io.ReadAll(r.Body)
		c.body = nil
		_ = json.Unmarshal(raw, &c.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func toolReq() Request {
	return Request{
		System: "You are a reviewer.",
		Messages: []Message{
			{Role: RoleUser, Text: "Look at app.py"},
			{Role: RoleAssistant, Text: "Reading.", ToolCalls: []ToolCall{{ID: "t1", Name: "read_file", Args: json.RawMessage(`{"path":"app.py"}`)}}},
			{Role: RoleTool, ToolResults: []ToolResult{{CallID: "t1", Name: "read_file", Content: "print(1)"}}},
		},
		Tools:     []ToolDef{{Name: "read_file", Description: "Read a file", Schema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`)}},
		MaxTokens: 1000,
	}
}

func TestAnthropicWireShape(t *testing.T) {
	c := serve(t, 200, `{"content":[{"type":"thinking","thinking":"","signature":"sig"},{"type":"text","text":"Calling."},{"type":"tool_use","id":"tu_1","name":"grep","input":{"pattern":"exec"}}],"stop_reason":"tool_use","usage":{"input_tokens":100,"output_tokens":20,"cache_read_input_tokens":300,"cache_creation_input_tokens":50}}`)
	p := NewAnthropic("claude-opus-5-5", c.srv.URL, "k-test", c.srv.Client())
	resp, err := p.Complete(context.Background(), toolReq())
	if err != nil {
		t.Fatal(err)
	}
	if c.path != "/v1/messages" || c.headers.Get("x-api-key") != "k-test" || c.headers.Get("anthropic-version") == "" {
		t.Fatalf("path=%s headers=%v", c.path, c.headers)
	}
	for _, banned := range []string{"temperature", "top_p", "top_k", "thinking", "tool_choice"} {
		if _, ok := c.body[banned]; ok {
			t.Errorf("request sends %q, which current Claude models reject", banned)
		}
	}
	if c.body["model"] != "claude-opus-5-5" || c.body["system"] != "You are a reviewer." || c.body["max_tokens"].(float64) != 1000 {
		t.Fatalf("body = %v", c.body)
	}
	msgs := c.body["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("messages = %d", len(msgs))
	}
	// Tool results go back as a user turn with tool_result blocks.
	last := msgs[2].(map[string]any)
	block := last["content"].([]any)[0].(map[string]any)
	if last["role"] != "user" || block["type"] != "tool_result" || block["tool_use_id"] != "t1" {
		t.Fatalf("tool result turn = %v", last)
	}
	tool := c.body["tools"].([]any)[0].(map[string]any)
	if tool["name"] != "read_file" || tool["input_schema"] == nil {
		t.Fatalf("tool = %v", tool)
	}

	if resp.StopReason != StopToolUse || resp.Text != "Calling." || len(resp.ToolCalls) != 1 || resp.ToolCalls[0].Name != "grep" || resp.ToolCalls[0].ID != "tu_1" {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.Usage.InputTokens != 450 || resp.Usage.OutputTokens != 20 || resp.Usage.CachedInputTokens != 300 || resp.Usage.CacheWriteTokens != 50 || resp.Usage.Estimated {
		t.Fatalf("usage = %+v", resp.Usage)
	}
	// The raw content, thinking block included, must be replayable.
	if !strings.Contains(string(resp.Raw), `"signature":"sig"`) {
		t.Fatalf("raw content lost the thinking block: %s", resp.Raw)
	}
}

func TestAnthropicReplaysAssistantTurnsVerbatim(t *testing.T) {
	c := serve(t, 200, `{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	p := NewAnthropic("m", c.srv.URL, "k", c.srv.Client())
	raw := json.RawMessage(`[{"type":"thinking","thinking":"","signature":"abc"},{"type":"tool_use","id":"tu_9","name":"grep","input":{}}]`)
	req := Request{Messages: []Message{
		{Role: RoleUser, Text: "go"},
		{Role: RoleAssistant, Raw: raw, ToolCalls: []ToolCall{{ID: "tu_9", Name: "grep"}}},
		{Role: RoleTool, ToolResults: []ToolResult{{CallID: "tu_9", Content: ""}}},
	}}
	if _, err := p.Complete(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	assistant := c.body["messages"].([]any)[1].(map[string]any)
	got, _ := json.Marshal(assistant["content"])
	if !strings.Contains(string(got), `"signature":"abc"`) {
		t.Fatalf("assistant turn was rebuilt instead of replayed: %s", got)
	}
}

func TestAnthropicRefusalAndTruncation(t *testing.T) {
	c := serve(t, 200, `{"content":[],"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber","explanation":"declined"},"usage":{"input_tokens":5,"output_tokens":0}}`)
	p := NewAnthropic("m", c.srv.URL, "k", c.srv.Client())
	resp, err := p.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Text: "x"}}})
	if err != nil || resp.StopReason != StopRefusal || !strings.Contains(resp.RefusalNote, "cyber") {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}

	c2 := serve(t, 200, `{"content":[{"type":"tool_use","id":"t","name":"grep","input":{"pat":"un"}}],"stop_reason":"max_tokens","usage":{"input_tokens":5,"output_tokens":9}}`)
	p2 := NewAnthropic("m", c2.srv.URL, "k", c2.srv.Client())
	resp, err = p2.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Text: "x"}}})
	if err != nil || resp.StopReason != StopMaxTokens || len(resp.ToolCalls) != 0 {
		t.Fatalf("a truncated tool call must not be returned for execution: %+v %v", resp, err)
	}
}

func TestOpenAIWireShape(t *testing.T) {
	c := serve(t, 200, `{"choices":[{"message":{"content":null,"tool_calls":[{"id":"call_a","type":"function","function":{"name":"grep","arguments":"{\"pattern\":\"exec\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":120,"completion_tokens":15,"prompt_tokens_details":{"cached_tokens":64}}}`)
	p := NewOpenAI("openai", "gpt-test", c.srv.URL+"/v1", "sk-test-key", c.srv.Client())
	resp, err := p.Complete(context.Background(), toolReq())
	if err != nil {
		t.Fatal(err)
	}
	if c.path != "/v1/chat/completions" || c.headers.Get("Authorization") != "Bearer sk-test-key" {
		t.Fatalf("path=%s auth=%q", c.path, c.headers.Get("Authorization"))
	}
	if _, ok := c.body["max_tokens"]; ok {
		t.Error("the openai provider must send max_completion_tokens, not max_tokens")
	}
	if c.body["max_completion_tokens"].(float64) != 1000 {
		t.Fatalf("body = %v", c.body)
	}
	msgs := c.body["messages"].([]any)
	if len(msgs) != 4 || msgs[0].(map[string]any)["role"] != "system" {
		t.Fatalf("messages = %v", msgs)
	}
	asst := msgs[2].(map[string]any)
	call := asst["tool_calls"].([]any)[0].(map[string]any)
	if call["id"] != "t1" || call["function"].(map[string]any)["arguments"] != `{"path":"app.py"}` {
		t.Fatalf("assistant tool call = %v", call)
	}
	toolMsg := msgs[3].(map[string]any)
	if toolMsg["role"] != "tool" || toolMsg["tool_call_id"] != "t1" {
		t.Fatalf("tool message = %v", toolMsg)
	}
	if resp.StopReason != StopToolUse || resp.ToolCalls[0].ID != "call_a" || string(resp.ToolCalls[0].Args) != `{"pattern":"exec"}` {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.Usage.InputTokens != 120 || resp.Usage.CachedInputTokens != 64 || resp.Usage.Estimated {
		t.Fatalf("usage = %+v", resp.Usage)
	}
}

func TestOpenAICompatibleVariants(t *testing.T) {
	reply := `{"choices":[{"message":{"content":"hi"},"finish_reason":"stop"}]}`

	// A generic compatible server gets max_tokens and no usage, so usage is
	// estimated and marked as such.
	c := serve(t, 200, reply)
	p := NewOpenAI("openai-compatible", "local", c.srv.URL+"/v1", "", c.srv.Client())
	resp, err := p.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Text: "hello there"}}, MaxTokens: 50})
	if err != nil {
		t.Fatal(err)
	}
	if c.body["max_tokens"].(float64) != 50 || c.headers.Get("Authorization") != "" {
		t.Fatalf("body=%v auth=%q", c.body, c.headers.Get("Authorization"))
	}
	if !resp.Usage.Estimated || resp.Usage.InputTokens == 0 || resp.StopReason != StopEnd {
		t.Fatalf("resp = %+v", resp)
	}

	// A base URL with a query string (Azure style) keeps it.
	c2 := serve(t, 200, reply)
	p2 := NewOpenAI("openai-compatible", "dep", c2.srv.URL+"/openai/deployments/dep?api-version=2024-10-21", "k", c2.srv.Client())
	if _, err := p2.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Text: "x"}}}); err != nil {
		t.Fatal(err)
	}
	if c2.path != "/openai/deployments/dep/chat/completions?api-version=2024-10-21" {
		t.Fatalf("path = %s", c2.path)
	}
}

func TestOpenRouterReportedCostIsUsed(t *testing.T) {
	p := NewOpenAI("openai-compatible", "x/y", "https://openrouter.ai/api/v1", "k", nil)
	if !p.isOpenRouter() {
		t.Fatal("openrouter host not recognized")
	}
	c := serve(t, 200, `{"choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"cost":0.00042}}`)
	p2 := NewOpenAI("openai-compatible", "x/y", c.srv.URL, "k", c.srv.Client())
	resp, err := p2.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Text: "x"}}})
	if err != nil || !resp.Usage.CostKnown || resp.Usage.CostUSD != 0.00042 {
		t.Fatalf("usage=%+v err=%v", resp.Usage, err)
	}
	// The pricer must keep a provider-reported cost.
	if got := NewPricer(nil).Cost("x/y", false, resp.Usage); got.CostUSD != 0.00042 || !got.CostKnown {
		t.Fatalf("pricer overwrote the reported cost: %+v", got)
	}
}

func TestOllamaWireShape(t *testing.T) {
	c := serve(t, 200, `{"message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"grep","arguments":{"pattern":"exec"}}}]},"done_reason":"stop","prompt_eval_count":80,"eval_count":12}`)
	p := NewOllama("qwen3:8b", c.srv.URL, c.srv.Client())
	resp, err := p.Complete(context.Background(), toolReq())
	if err != nil {
		t.Fatal(err)
	}
	if c.path != "/api/chat" || c.body["stream"] != false || c.body["model"] != "qwen3:8b" {
		t.Fatalf("path=%s body=%v", c.path, c.body)
	}
	msgs := c.body["messages"].([]any)
	asst := msgs[2].(map[string]any)
	args := asst["tool_calls"].([]any)[0].(map[string]any)["function"].(map[string]any)["arguments"]
	if _, isObject := args.(map[string]any); !isObject {
		t.Fatalf("ollama wants tool arguments as a JSON object, got %T", args)
	}
	if msgs[3].(map[string]any)["tool_name"] != "read_file" {
		t.Fatalf("tool message = %v", msgs[3])
	}
	if resp.StopReason != StopToolUse || string(resp.ToolCalls[0].Args) != `{"pattern":"exec"}` || resp.Usage.InputTokens != 80 {
		t.Fatalf("resp = %+v", resp)
	}
	if !p.Local() {
		t.Fatal("a loopback ollama must report Local")
	}
}

func TestOllamaProbeWarnsAboutSmallOrToolLessModels(t *testing.T) {
	c := serve(t, 200, `{"capabilities":["completion"],"details":{"parameter_size":"8.2B","quantization_level":"Q4_K_M"}}`)
	p := NewOllama("small", c.srv.URL, c.srv.Client())
	note, warnings, err := p.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(warnings, "|")
	if !strings.Contains(note, "8.2B") || !strings.Contains(joined, "tool calling") || !strings.Contains(joined, "small") {
		t.Fatalf("note=%q warnings=%v", note, warnings)
	}

	big := serve(t, 200, `{"capabilities":["completion","tools"],"details":{"parameter_size":"32.8B"}}`)
	_, warnings, err = NewOllama("big", big.srv.URL, big.srv.Client()).Probe(context.Background())
	if err != nil || len(warnings) != 0 {
		t.Fatalf("warnings=%v err=%v", warnings, err)
	}

	missing := serve(t, 404, `{"error":"model 'nope' not found"}`)
	_, _, err = NewOllama("nope", missing.srv.URL, missing.srv.Client()).Probe(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ollama pull nope") {
		t.Fatalf("got %v", err)
	}
}

func TestAPIErrorsAreExplainedAndNotRetriedWhenPermanent(t *testing.T) {
	c := serve(t, 401, `{"error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
	p := NewAnthropic("m", c.srv.URL, "bad", c.srv.Client())
	_, err := p.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Text: "x"}}})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 401 || !strings.Contains(apiErr.Message, "invalid x-api-key") || apiErr.Hint() == "" {
		t.Fatalf("err = %v", err)
	}
	if c.calls.Load() != 1 {
		t.Fatalf("a 401 was retried %d times", c.calls.Load()-1)
	}
	if strings.Contains(err.Error(), "bad") {
		t.Fatal("the error message echoes the API key")
	}
}

func TestProbeUsesFreeEndpoints(t *testing.T) {
	c := serve(t, 200, `{"id":"claude-opus-5-5","display_name":"Claude Opus 5.5","max_input_tokens":1000000}`)
	note, _, err := NewAnthropic("claude-opus-5-5", c.srv.URL, "k", c.srv.Client()).Probe(context.Background())
	if err != nil || c.path != "/v1/models/claude-opus-5-5" || !strings.Contains(note, "Claude Opus 5.5") {
		t.Fatalf("note=%q path=%s err=%v", note, c.path, err)
	}

	list := serve(t, 200, `{"data":[{"id":"a"},{"id":"b"}]}`)
	if _, _, err := NewOpenAI("openai", "b", list.srv.URL, "k", list.srv.Client()).Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _, err = NewOpenAI("openai", "zzz", list.srv.URL, "k", list.srv.Client()).Probe(context.Background())
	if err == nil || !strings.Contains(err.Error(), `"zzz" is not in the list`) {
		t.Fatalf("got %v", err)
	}
	noList := serve(t, 404, `{}`)
	note, _, err = NewOpenAI("openai-compatible", "m", noList.srv.URL, "k", noList.srv.Client()).Probe(context.Background())
	if err != nil || !strings.Contains(note, "not verified") {
		t.Fatalf("note=%q err=%v", note, err)
	}
}

func TestRedactingKeepsSecretsFromTheProvider(t *testing.T) {
	aws := "AKIA" + "IOSFODNN7EXAMPLE"
	pw := "tr0ub4dor-" + "fixture-9Zq2Lm7x"
	fake := NewFake(Say("ok"))
	p := NewRedacting(fake)
	_, err := p.Complete(context.Background(), Request{
		System: "key in system: " + aws,
		Messages: []Message{
			{Role: RoleUser, Text: `config has password = "` + pw + `"`},
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "1", Name: "grep", Args: json.RawMessage(`{"pattern":"` + aws + `"}`)}}},
			{Role: RoleTool, ToolResults: []ToolResult{{CallID: "1", Content: "found " + aws + " in settings.py"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sent := fake.Sent()
	if strings.Contains(sent, aws) || strings.Contains(sent, pw) {
		t.Fatalf("a secret reached the provider: %s", sent)
	}
	if !strings.Contains(sent, "[REDACTED:") || p.Redactions() < 4 {
		t.Fatalf("redactions=%d sent=%s", p.Redactions(), sent)
	}
}

func TestRedactingDropsRawTurnThatContainsASecret(t *testing.T) {
	aws := "AKIA" + "IOSFODNN7EXAMPLE"
	fake := NewFake(Say("ok"))
	p := NewRedacting(fake)
	raw := json.RawMessage(`[{"type":"text","text":"the key is ` + aws + `"}]`)
	_, err := p.Complete(context.Background(), Request{Messages: []Message{
		{Role: RoleUser, Text: "x"},
		{Role: RoleAssistant, Text: "the key is " + aws, Raw: raw},
		{Role: RoleUser, Text: "y"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fake.Sent(), aws) {
		t.Fatal("a secret inside a replayed raw turn reached the provider")
	}
	if fake.Requests[0].Messages[1].Raw != nil {
		t.Fatal("the raw turn should have been dropped so it is rebuilt from cleaned text")
	}
}

func env(vals map[string]string) func(string) string {
	return func(k string) string { return vals[k] }
}

func TestNewRefusesRemoteProvidersWhenOffline(t *testing.T) {
	keys := env(map[string]string{"ANTHROPIC_API_KEY": "k", "OPENAI_API_KEY": "k", "SPACKLE_API_KEY": "k"})
	remote := []config.Model{
		{Provider: "anthropic", Model: "claude-opus-5-5"},
		{Provider: "openai", Model: "m"},
		{Provider: "openai-compatible", Model: "m", BaseURL: "https://openrouter.ai/api/v1"},
		{Provider: "ollama", Model: "m", BaseURL: "http://192.168.1.20:11434"},
		{Provider: "openai-compatible", Model: "m", BaseURL: "http://localhost.evil.example:8000/v1"},
	}
	for _, m := range remote {
		if _, err := New(m, Options{Offline: true, Getenv: keys}); !errors.Is(err, ErrOffline) {
			t.Errorf("%s %s: err = %v, want ErrOffline", m.Provider, m.BaseURL, err)
		}
	}
	local := []config.Model{
		{Provider: "ollama", Model: "m"},
		{Provider: "ollama", Model: "m", BaseURL: "http://[::1]:11434"},
		{Provider: "openai-compatible", Model: "m", BaseURL: "http://localhost:8080/v1"},
	}
	for _, m := range local {
		p, err := New(m, Options{Offline: true, Getenv: keys})
		if err != nil {
			t.Errorf("%s %s: %v", m.Provider, m.BaseURL, err)
			continue
		}
		if _, ok := p.(*Redacting); !ok {
			t.Errorf("New must return a redacting provider, got %T", p)
		}
	}
}

func TestOfflineDialerRefusesNonLoopback(t *testing.T) {
	client := NewHTTPClient(true)
	// 192.0.2.1 is TEST-NET-1: reserved for documentation, never routed.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://192.0.2.1:9/", nil)
	_, err := client.Do(req) //nolint:bodyclose // the request must fail before any response exists
	if err == nil || !errors.Is(err, ErrOffline) {
		t.Fatalf("err = %v, want ErrOffline", err)
	}

	// Loopback still works in offline mode.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("loopback request failed in offline mode: %v", err)
	}
	_ = resp.Body.Close()
}

func TestNewKeyHandling(t *testing.T) {
	none := env(nil)
	_, err := New(config.Model{Provider: "anthropic", Model: "m"}, Options{Getenv: none})
	if err == nil || !strings.Contains(err.Error(), "ANTHROPIC_API_KEY") || !strings.Contains(err.Error(), "subscription is not API access") {
		t.Fatalf("got %v", err)
	}
	_, err = New(config.Model{Provider: "openai-compatible", Model: "m", BaseURL: "https://openrouter.ai/api/v1", APIKeyEnv: "OPENROUTER_API_KEY"}, Options{Getenv: none})
	if err == nil || !strings.Contains(err.Error(), "OPENROUTER_API_KEY") {
		t.Fatalf("got %v", err)
	}
	// A local compatible server needs no key.
	if _, err := New(config.Model{Provider: "openai-compatible", Model: "m", BaseURL: "http://127.0.0.1:8080/v1"}, Options{Getenv: none}); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config.Model{}, Options{Getenv: none}); err == nil {
		t.Fatal("an unconfigured model must be an error")
	}
}

func TestPricer(t *testing.T) {
	p := NewPricer(map[string]Price{"custom": {Input: 1, Output: 2}})
	u := p.Cost("claude-opus-5-5", false, Usage{InputTokens: 1_000_000, OutputTokens: 1_000_000})
	if !u.CostKnown || u.CostUSD != 24 {
		t.Fatalf("opus 5.5 cost = %+v, want 24", u)
	}
	// 600k plain at $4, 400k cache reads at $0.20.
	u = p.Cost("claude-opus-5-5", false, Usage{InputTokens: 1_000_000, CachedInputTokens: 400_000})
	if want := 0.6*4 + 0.4*0.20; u.CostUSD < want-1e-9 || u.CostUSD > want+1e-9 {
		t.Fatalf("cached cost = %v, want %v", u.CostUSD, want)
	}
	if u := p.Cost("custom", false, Usage{InputTokens: 1_000_000}); u.CostUSD != 1 {
		t.Fatalf("override cost = %+v", u)
	}
	if u := p.Cost("mystery-model", false, Usage{InputTokens: 1000}); u.CostKnown || u.CostUSD != 0 {
		t.Fatalf("an unpriced model must be cost-unknown, got %+v", u)
	}
	if u := p.Cost("mystery-model", true, Usage{InputTokens: 1000}); !u.CostKnown || u.CostUSD != 0 {
		t.Fatalf("a local model costs nothing and that is known, got %+v", u)
	}
}

func TestLoopbackDetection(t *testing.T) {
	yes := []string{"http://localhost:11434", "http://127.0.0.1:8080/v1", "http://[::1]:1", "http://app.localhost/", "http://127.9.9.9"}
	no := []string{"https://api.anthropic.com", "http://192.168.0.2", "http://10.0.0.1", "http://localhost.example.com", "http://0.0.0.0:80", "", "not a url"}
	for _, u := range yes {
		if !IsLoopbackURL(u) {
			t.Errorf("%s should be loopback", u)
		}
	}
	for _, u := range no {
		if IsLoopbackURL(u) {
			t.Errorf("%s should not be loopback", u)
		}
	}
}

func TestFakeScript(t *testing.T) {
	f := NewFake(Call("1", "grep", map[string]string{"pattern": "x"}), Say("done"))
	r1, _ := f.Complete(context.Background(), Request{})
	r2, _ := f.Complete(context.Background(), Request{})
	if r1.StopReason != StopToolUse || r2.StopReason != StopEnd || r2.Text != "done" || f.Remaining() != 0 {
		t.Fatalf("r1=%+v r2=%+v", r1, r2)
	}
	if _, err := f.Complete(context.Background(), Request{}); err == nil {
		t.Fatal("an exhausted script must be an error, not a silent empty response")
	}
}
