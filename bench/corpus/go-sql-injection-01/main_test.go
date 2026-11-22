package main

import "testing"

func TestClampLimit(t *testing.T) {
	cases := map[string]int{"": 20, "abc": 20, "0": 20, "5": 5, "500": 100}
	for in, want := range cases {
		if got := clampLimit(in); got != want {
			t.Errorf("clampLimit(%q) = %d, want %d", in, got, want)
		}
	}
}
