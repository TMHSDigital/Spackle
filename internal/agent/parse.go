package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// extractJSON finds the JSON object in a model's reply. Models wrap JSON in
// prose or code fences even when told not to, so this takes the first
// balanced top-level object rather than requiring the reply to be pure JSON.
func extractJSON(text string) ([]byte, error) {
	start := strings.IndexByte(text, '{')
	if start < 0 {
		return nil, errors.New("the reply contains no JSON object")
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(text); i++ {
		c := text[i]
		switch {
		case escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
			// characters inside a string do not affect nesting
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				obj := []byte(text[start : i+1])
				if !json.Valid(obj) {
					return nil, errors.New("the reply contains a JSON object that does not parse")
				}
				return obj, nil
			}
		}
	}
	return nil, errors.New("the reply contains a JSON object that is cut off")
}

// decodeReply extracts the JSON object from a reply and decodes it into v.
// Unknown fields are tolerated: a model adding a field is not a reason to
// throw away an otherwise valid answer.
func decodeReply(text string, v any) error {
	raw, err := extractJSON(text)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("the reply's JSON has the wrong shape: %w", err)
	}
	return nil
}
