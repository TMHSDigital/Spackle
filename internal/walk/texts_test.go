package walk

import (
	"strings"
	"testing"
)

func TestTextsHandsATextOverOnce(t *testing.T) {
	texts := NewTexts()
	texts.Put("a", "one")
	texts.Put("a", "two") // the first text for a path is kept
	if got, ok := texts.Get("a"); !ok || got != "one" {
		t.Fatalf("Get = %q, %v", got, ok)
	}
	if got, ok := texts.Take("a"); !ok || got != "one" {
		t.Fatalf("Take = %q, %v", got, ok)
	}
	if _, ok := texts.Take("a"); ok {
		t.Fatal("a text was handed over twice")
	}
	if _, ok := texts.Get("missing"); ok {
		t.Fatal("a text that was never kept was returned")
	}
}

func TestTextsHoldsABoundedAmount(t *testing.T) {
	texts := NewTexts()
	half := strings.Repeat("x", MaxHeldText/2)
	texts.Put("a", half)
	texts.Put("b", half)
	texts.Put("c", "y") // no room: not kept, the reader reads the file itself
	if _, ok := texts.Get("c"); ok {
		t.Fatal("a text was kept past the limit")
	}
	if _, ok := texts.Take("a"); !ok {
		t.Fatal("a text within the limit was not kept")
	}
	texts.Put("c", "y") // taking a text makes room again
	if _, ok := texts.Get("c"); !ok {
		t.Fatal("room freed by Take was not reused")
	}
}

func TestNilTextsHoldsNothing(t *testing.T) {
	var texts *Texts
	texts.Put("a", "one")
	if _, ok := texts.Get("a"); ok {
		t.Fatal("a nil Texts returned a text")
	}
	if _, ok := texts.Take("a"); ok {
		t.Fatal("a nil Texts returned a text")
	}
}
