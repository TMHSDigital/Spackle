// Package textx holds the one helper that bounds a string before it goes
// into a ledger event, a prompt, a report field or an error message.
package textx

import "unicode/utf8"

// Clip returns s cut to at most maxBytes bytes, with "..." appended when
// anything was cut. The cut never falls inside a UTF-8 sequence, so clipped
// model output or program output stays valid text.
func Clip(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes < 0 {
		maxBytes = 0
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes] + "..."
}
