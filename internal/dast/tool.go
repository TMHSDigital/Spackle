package dast

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/TMHSDigital/spackle/internal/agent/tools"
	"github.com/TMHSDigital/spackle/internal/authz"
	"github.com/TMHSDigital/spackle/internal/llm"
)

// maxToolBody is how much of a response body one tool result shows.
const maxToolBody = 6000

const httpToolSchema = `{"type":"object","properties":{` +
	`"method":{"type":"string","description":"HTTP method in upper case. Defaults to GET. Methods that change state are refused unless the operator's scope allows them."},` +
	`"url":{"type":"string","description":"A path relative to the target base (for example /search?q=1) or an absolute URL inside the authorized scope."},` +
	`"headers":{"type":"object","additionalProperties":{"type":"string"},"description":"Extra request headers."},` +
	`"body":{"type":"string","description":"Request body, sent as given."}` +
	`},"required":["url"],"additionalProperties":false}`

type httpTool struct {
	c    *Client
	base *url.URL
}

type httpArgs struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// HTTPTool returns the investigator tool "http_request" bound to the client. Its arguments
// are {"method": "GET", "url": "/path?x=1", "headers": {...}, "body": "..."}, where url is a
// path relative to base or an absolute in-scope URL. The result is the exchange id, the status
// line, the response headers and the first 6000 bytes of the body. A request outside the scope,
// or with a method the scope does not allow, is an error from Run that explains the scope
// rule. The tool has no argument that reaches the scope, the request cap or the rate limit.
func HTTPTool(c *Client, base *url.URL) tools.Tool {
	return httpTool{c: c, base: base}
}

func (t httpTool) Def() llm.ToolDef {
	return llm.ToolDef{
		Name: "http_request",
		Description: "Send one HTTP request to the running target and return the status, response headers and the start of the body. " +
			"Only URLs inside the operator's authorized scope are sent; anything else is refused. " +
			"Redirects are followed only while they stay in scope. Every request counts against a fixed request cap, so send only requests that test a specific hypothesis.",
		Schema: json.RawMessage(httpToolSchema),
	}
}

func (t httpTool) Run(ctx context.Context, args json.RawMessage) (string, error) {
	if t.c == nil || t.base == nil {
		return "", errors.New("http_request is not connected to an authorized target in this run; continue without live requests")
	}
	var a httpArgs
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return "", fmt.Errorf("invalid arguments (%s); send one JSON object with only the fields method, url, headers and body", show(err.Error(), 150))
	}
	if dec.More() {
		return "", errors.New("invalid arguments (extra data after the JSON object); send exactly one JSON object")
	}
	if strings.TrimSpace(a.URL) == "" {
		return "", errors.New(`the url field is required; send a path such as "/search?q=1" or an absolute URL inside the authorized scope`)
	}
	if a.Method == "" {
		a.Method = http.MethodGet
	}
	ref, err := url.Parse(strings.TrimSpace(a.URL))
	if err != nil {
		return "", fmt.Errorf("the url %s could not be parsed; send a path such as \"/search?q=1\" or an absolute http or https URL", show(a.URL, 80))
	}
	target := t.base.ResolveReference(ref)

	var body []byte
	if a.Body != "" {
		body = []byte(a.Body)
	}
	ex, err := t.c.Do(ctx, a.Method, target.String(), a.Headers, body)
	switch {
	case errors.Is(err, authz.ErrNotAuthorized):
		return "", fmt.Errorf("refused by the authorized scope, nothing was sent: %s. The scope is set by the operator and cannot be changed from here; work within it", show(redacted(err.Error()), 500))
	case errors.Is(err, ErrRequestCap):
		return "", errors.New("the request cap for this run has been reached, so no more requests can be sent; finish with the evidence already collected")
	case err != nil && ex.ID == "":
		return "", fmt.Errorf("the request was not sent: %s", show(redacted(err.Error()), 300))
	case err != nil:
		return "", fmt.Errorf("the request got no response (recorded as exchange %s): %s", ex.ID, show(ex.Error, 300))
	}
	return renderExchange(ex), nil
}

// renderExchange formats an exchange for the model. The text comes from the
// recorded exchange, so it is already redacted.
func renderExchange(ex Exchange) string {
	var b strings.Builder
	fmt.Fprintf(&b, "exchange %s\n%s %s\nHTTP %d %s\n", ex.ID, ex.Method, ex.URL, ex.Status, http.StatusText(ex.Status))
	names := make([]string, 0, len(ex.RespHeaders))
	for name := range ex.RespHeaders {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, line := range strings.Split(ex.RespHeaders[name], "\n") {
			fmt.Fprintf(&b, "%s: %s\n", name, line)
		}
	}
	if ex.Note != "" {
		fmt.Fprintf(&b, "[note: %s]\n", ex.Note)
	}
	if ex.Error != "" {
		fmt.Fprintf(&b, "[error: %s]\n", ex.Error)
	}
	b.WriteString("\n")
	body := ex.RespBody
	if len(body) > maxToolBody {
		cut := maxToolBody
		for cut > 0 && !utf8.RuneStart(body[cut]) {
			cut--
		}
		fmt.Fprintf(&b, "%s\n[body truncated: %d more bytes were recorded; request a narrower resource to see more]\n", body[:cut], len(body)-cut)
	} else {
		b.WriteString(body)
	}
	return b.String()
}
