package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxResponseBytes caps a provider response so a faulty endpoint cannot
// exhaust memory. It is a variable only so tests can lower it.
var maxResponseBytes int64 = 32 << 20

// retryWait returns how long doJSON waits before the given attempt, counted
// from 1. It is a variable only so tests can shorten the wait.
var retryWait = func(attempt int) time.Duration {
	return time.Duration(attempt-1) * 2 * time.Second
}

// errUndecodable marks a response with a success status whose body could not
// be decoded. The provider has already done, and charged for, the work, so
// doJSON does not send the request again.
type errUndecodable struct{ err error }

func (e *errUndecodable) Error() string { return e.err.Error() }
func (e *errUndecodable) Unwrap() error { return e.err }

// doJSON sends a JSON request and decodes a JSON response, retrying
// transient failures with backoff. headers must not be logged: they carry
// the API key.
func doJSON(ctx context.Context, client *http.Client, provider, method, url string, headers map[string]string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return fmt.Errorf("encode %s request: %w", provider, err)
		}
	}
	const attempts = 3
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryWait(attempt)):
			}
		}
		err := doOnce(ctx, client, provider, method, url, headers, payload, out)
		if err == nil {
			return nil
		}
		lastErr = err
		var apiErr *APIError
		if errors.As(err, &apiErr) && !apiErr.Retryable() {
			return err
		}
		var undecodable *errUndecodable
		if errors.As(err, &undecodable) {
			return err
		}
		if errors.Is(err, ErrOffline) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	return lastErr
}

func doOnce(ctx context.Context, client *http.Client, provider, method, url string, headers map[string]string, payload []byte, out any) error {
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return fmt.Errorf("build %s request: %w", provider, err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "spackle")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, ErrOffline) {
			return err
		}
		return fmt.Errorf("%s request failed: %w. Check the network and base_url", provider, scrubURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read %s response: %w", provider, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{Provider: provider, Status: resp.StatusCode, Message: errorMessage(data)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return &errUndecodable{fmt.Errorf("%s returned a response that is not the expected JSON: %w. Check that base_url points at the API root", provider, err)}
	}
	return nil
}

// scrubURLError keeps a transport error from echoing a URL that might hold
// credentials in its query string (some Azure-style endpoints do).
func scrubURLError(err error) error {
	msg := err.Error()
	if i := strings.Index(msg, "?"); i >= 0 {
		if j := strings.IndexAny(msg[i:], "\": "); j > 0 {
			msg = msg[:i] + "?[query removed]" + msg[i+j:]
		}
	}
	return errors.New(msg)
}

// errorMessage extracts a human-readable message from a provider error body.
func errorMessage(data []byte) string {
	var shapes struct {
		Error json.RawMessage `json:"error"`
		Msg   string          `json:"message"`
	}
	if json.Unmarshal(data, &shapes) == nil {
		if len(shapes.Error) > 0 {
			var obj struct {
				Message string `json:"message"`
				Type    string `json:"type"`
			}
			if json.Unmarshal(shapes.Error, &obj) == nil && obj.Message != "" {
				return truncate(obj.Message, 400)
			}
			var s string
			if json.Unmarshal(shapes.Error, &s) == nil && s != "" {
				return truncate(s, 400)
			}
		}
		if shapes.Msg != "" {
			return truncate(shapes.Msg, 400)
		}
	}
	return truncate(strings.TrimSpace(string(data)), 400)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
