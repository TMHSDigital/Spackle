package main

import "testing"

func TestContentType(t *testing.T) {
	cases := map[string]string{
		"notes.txt":   "text/plain; charset=utf-8",
		"data.JSON":   "application/json",
		"report.pdf":  "application/pdf",
		"archive.bin": "application/octet-stream",
	}
	for name, want := range cases {
		if got := contentType(name); got != want {
			t.Errorf("contentType(%q) = %q, want %q", name, got, want)
		}
	}
}
