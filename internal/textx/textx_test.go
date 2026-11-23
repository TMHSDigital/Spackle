package textx

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClip(t *testing.T) {
	for _, c := range []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"shorter than the limit", "abc", 10, "abc"},
		{"exactly the limit", "abc", 3, "abc"},
		{"one byte over", "abcd", 3, "abc..."},
		{"empty", "", 0, ""},
		{"limit zero", "abc", 0, "..."},
		{"negative limit", "abc", -5, "..."},
		// é is 2 bytes, € is 3 and 😀 is 4: a cut inside one backs up to its start.
		{"inside a 2 byte sequence", "aé", 2, "a..."},
		{"after a 2 byte sequence", "aéb", 3, "aé..."},
		{"inside a 3 byte sequence, first byte", "a€", 2, "a..."},
		{"inside a 3 byte sequence, second byte", "a€", 3, "a..."},
		{"inside a 4 byte sequence", "a😀", 4, "a..."},
		{"after a 4 byte sequence", "a😀b", 5, "a😀..."},
		{"only a multi-byte character", "😀", 2, "..."},
	} {
		got := Clip(c.in, c.max)
		if got != c.want {
			t.Errorf("%s: Clip(%q, %d) = %q, want %q", c.name, c.in, c.max, got, c.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("%s: Clip(%q, %d) = %q is not valid UTF-8", c.name, c.in, c.max, got)
		}
	}
}

func TestClipNeverSplitsACharacter(t *testing.T) {
	text := strings.Repeat("aé€😀", 20)
	for limit := 0; limit <= len(text); limit++ {
		got := Clip(text, limit)
		if !utf8.ValidString(got) {
			t.Fatalf("Clip at %d bytes is not valid UTF-8: %q", limit, got)
		}
		if body := strings.TrimSuffix(got, "..."); len(body) > limit || !strings.HasPrefix(text, body) {
			t.Fatalf("Clip at %d bytes kept %d bytes that are not a prefix: %q", limit, len(body), got)
		}
	}
}
