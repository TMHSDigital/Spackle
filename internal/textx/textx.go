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
	return Cut(s, maxBytes) + "..."
}

// Cut returns the longest prefix of s that is at most maxBytes bytes long
// and does not end inside a UTF-8 sequence. It adds nothing: it is for a
// caller that says in its own words that text was cut.
func Cut(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes < 0 {
		maxBytes = 0
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}
