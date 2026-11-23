package llm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// reply is one scripted answer of a sequence server.
type reply struct {
	status int
	body   string
}

// sequence is a test server that answers each request with the next scripted
// reply (the last one repeats) and records every request body it received.
type sequence struct {
	srv    *httptest.Server
	mu     sync.Mutex
	bodies []string
}

func serveSequence(t *testing.T, replies ...reply) *sequence {
	t.Helper()
	s := &sequence{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.bodies = append(s.bodies, string(raw))
		n := len(s.bodies)
		s.mu.Unlock()
		if n > len(replies) {
			n = len(replies)
		}
		w.WriteHeader(replies[n-1].status)
		_, _ = io.WriteString(w, replies[n-1].body)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *sequence) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bodies)
}

func (s *sequence) received() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.bodies...)
}

// noBackoff removes the retry wait for one test and returns the attempt
// numbers the retry loop asked a wait for.
func noBackoff(t *testing.T) *[]int {
	t.Helper()
	old := retryWait
	var asked []int
	retryWait = func(attempt int) time.Duration {
		asked = append(asked, attempt)
		return 0
	}
	t.Cleanup(func() { retryWait = old })
	return &asked
}

// roundTrip adapts a function to http.RoundTripper.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type pingRequest struct {
	Model string `json:"model"`
	N     int    `json:"n"`
}

type pingResponse struct {
	OK bool `json:"ok"`
}

func TestRetryWaitDefaultIsTwoSecondsPerEarlierAttempt(t *testing.T) {
	for attempt, want := range map[int]time.Duration{2: 2 * time.Second, 3: 4 * time.Second} {
		if got := retryWait(attempt); got != want {
			t.Errorf("retryWait(%d) = %v, want %v", attempt, got, want)
		}
	}
	if maxResponseBytes != 32<<20 {
		t.Errorf("maxResponseBytes = %d, want 32 MiB", maxResponseBytes)
	}
}

func TestDoJSONRetriesServerErrorsThenSucceeds(t *testing.T) {
	asked := noBackoff(t)
	s := serveSequence(t,
		reply{500, `{"error":{"message":"boom"}}`},
		reply{500, `{"error":{"message":"boom"}}`},
		reply{200, `{"ok":true}`},
	)
	var out pingResponse
	err := doJSON(context.Background(), s.srv.Client(), "anthropic", http.MethodPost, s.srv.URL, nil, pingRequest{Model: "m", N: 1}, &out)
	if err != nil {
		t.Fatalf("two 500s then a 200 must succeed, got %v", err)
	}
	if !out.OK {
		t.Fatalf("the 200 body was not decoded: %+v", out)
	}
	got := s.received()
	if len(got) != 3 {
		t.Fatalf("calls = %d, want 3", len(got))
	}
	for i, body := range got {
		if body != `{"model":"m","n":1}` {
			t.Errorf("attempt %d sent body %q, want the full request body", i+1, body)
		}
	}
	if len(*asked) != 2 || (*asked)[0] != 2 || (*asked)[1] != 3 {
		t.Fatalf("waits were asked for attempts %v, want [2 3]", *asked)
	}
}

func TestDoJSONGivesUpAfterThreeRetryableFailures(t *testing.T) {
	for _, status := range []int{408, 409, 429, 500, 503, 529} {
		noBackoff(t)
		s := serveSequence(t, reply{status, `{"error":{"type":"overloaded_error","message":"try later"}}`})
		err := doJSON(context.Background(), s.srv.Client(), "anthropic", http.MethodPost, s.srv.URL, nil, pingRequest{Model: "m"}, &pingResponse{})
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != status || apiErr.Provider != "anthropic" || apiErr.Message != "try later" {
			t.Errorf("HTTP %d: err = %v, want an *APIError with that status", status, err)
		}
		if n := s.calls(); n != 3 {
			t.Errorf("HTTP %d: calls = %d, want 3", status, n)
		}
	}
}

func TestDoJSONDoesNotRetryPermanentErrors(t *testing.T) {
	for _, status := range []int{400, 403, 404, 422} {
		asked := noBackoff(t)
		s := serveSequence(t, reply{status, `{"error":{"message":"no"}}`})
		err := doJSON(context.Background(), s.srv.Client(), "openai", http.MethodPost, s.srv.URL, nil, pingRequest{Model: "m"}, &pingResponse{})
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != status {
			t.Errorf("HTTP %d: err = %v, want an *APIError with that status", status, err)
		}
		if n := s.calls(); n != 1 {
			t.Errorf("HTTP %d: calls = %d, want exactly 1", status, n)
		}
		if len(*asked) != 0 {
			t.Errorf("HTTP %d: the retry loop waited before attempts %v", status, *asked)
		}
	}
}

func TestDoJSONDoesNotRepeatASuccessfulRequest(t *testing.T) {
	asked := noBackoff(t)
	s := serveSequence(t, reply{200, `{"ok":true}`})
	var out pingResponse
	if err := doJSON(context.Background(), s.srv.Client(), "openai", http.MethodPost, s.srv.URL, nil, pingRequest{Model: "m"}, &out); err != nil {
		t.Fatal(err)
	}
	if n := s.calls(); n != 1 || !out.OK || len(*asked) != 0 {
		t.Fatalf("calls = %d, out = %+v, waits = %v: a success must be sent once", n, out, *asked)
	}

	// A nil out discards the body and a nil body sends none.
	bare := serveSequence(t, reply{204, ""})
	if err := doJSON(context.Background(), bare.srv.Client(), "openai", http.MethodGet, bare.srv.URL, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := bare.received(); len(got) != 1 || got[0] != "" {
		t.Fatalf("requests = %q, want one request with no body", got)
	}
}

func TestDoJSONStopsWhenContextIsCancelledDuringTheWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := retryWait
	t.Cleanup(func() { retryWait = old })
	// The wait is far longer than the test: only the cancellation can end it.
	retryWait = func(int) time.Duration {
		time.AfterFunc(10*time.Millisecond, cancel)
		return time.Minute
	}
	s := serveSequence(t, reply{500, `{"error":{"message":"boom"}}`})
	start := time.Now()
	err := doJSON(ctx, s.srv.Client(), "anthropic", http.MethodPost, s.srv.URL, nil, pingRequest{Model: "m"}, &pingResponse{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if n := s.calls(); n != 1 {
		t.Fatalf("calls = %d, want no call after the cancellation", n)
	}
	if took := time.Since(start); took > 30*time.Second {
		t.Fatalf("the wait ignored the cancellation and took %v", took)
	}
}

func TestDoJSONKeepsAContextErrorFromTheLastAttempt(t *testing.T) {
	const key = "abcd1234efgh5678"
	for _, tc := range []struct {
		name     string
		deadline bool
		want     error
	}{
		{"cancelled", false, context.Canceled},
		{"deadline", true, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noBackoff(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			// Two attempts fail, and the context ends while the last one is
			// in flight, where no wait between attempts can catch it.
			client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls < 3 {
					return nil, errors.New("connection reset")
				}
				if !tc.deadline {
					cancel()
				}
				<-r.Context().Done()
				return nil, r.Context().Err()
			})}
			if tc.deadline {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 200*time.Millisecond)
				defer stop()
			}
			err := doJSON(ctx, client, "anthropic", http.MethodPost, "https://host.invalid/v1?api-key="+key, nil, pingRequest{Model: "m"}, &pingResponse{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want it to match %v", err, tc.want)
			}
			if calls != 3 {
				t.Fatalf("calls = %d, want the context to end during the third", calls)
			}
			if msg := err.Error(); strings.Contains(msg, "Check the network") || strings.Contains(msg, key) {
				t.Fatalf("err = %v, want no network hint and no query string", err)
			}
		})
	}
}

func TestDoJSONScrubsTransportErrors(t *testing.T) {
	noBackoff(t)
	const key = "abcd1234efgh5678"
	calls := 0
	client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("connection refused")
	})}
	endpoint := "https://host.invalid/path?api-key=" + key + "&v=1"
	err := doJSON(context.Background(), client, "openai-compatible", http.MethodPost, endpoint, map[string]string{"Authorization": "Bearer " + key}, pingRequest{Model: "m"}, &pingResponse{})
	if err == nil {
		t.Fatal("a failing transport must be an error")
	}
	msg := err.Error()
	if strings.Contains(msg, key) || strings.Contains(msg, "api-key") || strings.Contains(msg, "v=1") {
		t.Fatalf("the error echoes the query string: %s", msg)
	}
	for _, want := range []string{"?[query removed]", "openai-compatible request failed", "https://host.invalid/path", "connection refused", "Check the network and base_url"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not contain %q", msg, want)
		}
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want a transport failure to be tried 3 times", calls)
	}
}

func TestDoJSONDoesNotRetryAnOfflineRefusal(t *testing.T) {
	asked := noBackoff(t)
	calls := 0
	client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, ErrOffline
	})}
	err := doJSON(context.Background(), client, "openai", http.MethodPost, "https://host.invalid/v1", nil, pingRequest{Model: "m"}, &pingResponse{})
	if !errors.Is(err, ErrOffline) {
		t.Fatalf("err = %v, want ErrOffline", err)
	}
	if calls != 1 || len(*asked) != 0 {
		t.Fatalf("calls = %d, waits = %v: an offline refusal must not be retried", calls, *asked)
	}
}

func TestScrubURLError(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no question mark", `Post "https://host/path": connection refused`, `Post "https://host/path": connection refused`},
		{"empty message", ``, ``},
		{"question mark ends the message", `is the server up?`, `is the server up?`},
		{"question mark then a quote", `Get "https://host/path?": EOF`, `Get "https://host/path?[query removed]": EOF`},
		{"quoted url with a query", `Post "https://host/path?api-key=abcd1234&v=1": EOF`, `Post "https://host/path?[query removed]": EOF`},
		{"query ended by a space", `dial https://host/path?api-key=abcd1234 failed`, `dial https://host/path?[query removed] failed`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scrubURLError(errors.New(tc.in)).Error(); got != tc.want {
				t.Fatalf("scrubURLError(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	// With two query strings the first one is removed and the text between
	// them is kept.
	got := scrubURLError(errors.New(`Post "https://a.example/p?k=first-secret": via "https://b.example/q?x=1": EOF`)).Error()
	if strings.Contains(got, "first-secret") || !strings.Contains(got, `"https://a.example/p?[query removed]": via "https://b.example/q`) {
		t.Fatalf("two query strings: got %q", got)
	}
}

func TestDoJSONExplainsANonJSONSuccessBody(t *testing.T) {
	asked := noBackoff(t)
	s := serveSequence(t, reply{200, "<!DOCTYPE html><html><body>Welcome to nginx</body></html>"})
	var out pingResponse
	err := doJSON(context.Background(), s.srv.Client(), "ollama", http.MethodPost, s.srv.URL, nil, pingRequest{Model: "m"}, &out)
	if err == nil {
		t.Fatal("an HTML body must be an error")
	}
	for _, want := range []string{"ollama returned a response that is not the expected JSON", "Check that base_url points at the API root"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Fatalf("a 200 with a bad body is not an API error: %v", err)
	}
	// The provider already did the work: the request is not sent again.
	if n := s.calls(); n != 1 || len(*asked) != 0 {
		t.Fatalf("calls = %d, waits = %v: a 200 with a bad body must be requested once", n, *asked)
	}
}

func TestDoJSONCapsTheResponseBody(t *testing.T) {
	noBackoff(t)
	old := maxResponseBytes
	t.Cleanup(func() { maxResponseBytes = old })
	maxResponseBytes = 64

	type textResponse struct {
		Text string `json:"text"`
	}

	// A body within the limit is decoded whole.
	small := serveSequence(t, reply{200, `{"text":"` + strings.Repeat("a", 20) + `"}`})
	var out textResponse
	if err := doJSON(context.Background(), small.srv.Client(), "openai", http.MethodGet, small.srv.URL, nil, nil, &out); err != nil || len(out.Text) != 20 {
		t.Fatalf("out = %+v, err = %v", out, err)
	}

	// A valid body over the limit is cut at the limit, so it no longer parses.
	big := serveSequence(t, reply{200, `{"text":"` + strings.Repeat("a", 4096) + `"}`})
	out = textResponse{}
	err := doJSON(context.Background(), big.srv.Client(), "openai", http.MethodGet, big.srv.URL, nil, nil, &out)
	if err == nil {
		t.Fatalf("a body over the limit was read whole: %d bytes of text", len(out.Text))
	}
	if !strings.Contains(err.Error(), "is not the expected JSON") || !strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("err = %v, want the invalid JSON hint for a cut body", err)
	}
	if n := big.calls(); n != 1 {
		t.Fatalf("calls = %d, want 1: a response cut at the size limit must not be requested again", n)
	}

	// An error body over the limit is cut too, and still reported as the API
	// error it is.
	huge := serveSequence(t, reply{400, strings.Repeat("x", 4096)})
	err = doJSON(context.Background(), huge.srv.Client(), "openai", http.MethodGet, huge.srv.URL, nil, nil, &out)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 400 || apiErr.Message != strings.Repeat("x", 64) {
		t.Fatalf("err = %v, want a 400 whose message is the first 64 bytes", err)
	}
}
