package budget

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/llm"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func newBudget(t *testing.T, caps Caps) (*Budget, *fakeClock) {
	t.Helper()
	c := &fakeClock{now: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	b, err := New(caps, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	return b, c
}

var caps = Caps{Tokens: 1000, USD: 1, Wall: time.Minute, SandboxRuns: 2}

func TestCapsCannotBeTurnedOff(t *testing.T) {
	for _, c := range []Caps{
		{Tokens: 0, USD: 1, Wall: time.Minute, SandboxRuns: 1},
		{Tokens: 1, USD: 0, Wall: time.Minute, SandboxRuns: 1},
		{Tokens: 1, USD: 1, Wall: 0, SandboxRuns: 1},
		{Tokens: 1, USD: 1, Wall: time.Minute, SandboxRuns: 0},
		{Tokens: -5, USD: 1, Wall: time.Minute, SandboxRuns: 1},
	} {
		if _, err := New(c, nil); err == nil {
			t.Errorf("New(%+v) accepted a missing cap", c)
		}
	}
}

func TestEachCapTrips(t *testing.T) {
	b, _ := newBudget(t, caps)
	if err := b.Check(); err != nil {
		t.Fatal(err)
	}
	b.Charge(llm.Usage{InputTokens: 900, OutputTokens: 100, CostKnown: true})
	if err := b.Check(); !errors.Is(err, ErrExhausted) || !strings.Contains(err.Error(), "token cap") {
		t.Fatalf("token cap: %v", err)
	}

	b, _ = newBudget(t, caps)
	b.Charge(llm.Usage{InputTokens: 10, CostUSD: 1.0, CostKnown: true})
	if err := b.Check(); !errors.Is(err, ErrExhausted) || !strings.Contains(err.Error(), "spend cap") {
		t.Fatalf("spend cap: %v", err)
	}

	b, clock := newBudget(t, caps)
	clock.now = clock.now.Add(61 * time.Second)
	if err := b.Check(); !errors.Is(err, ErrExhausted) || !strings.Contains(err.Error(), "wall time") {
		t.Fatalf("wall cap: %v", err)
	}
	if b.Remaining() != 0 {
		t.Fatalf("remaining = %s", b.Remaining())
	}

	b, _ = newBudget(t, caps)
	for i := 0; i < 2; i++ {
		if err := b.UseSandbox(); err != nil {
			t.Fatalf("sandbox run %d should fit: %v", i+1, err)
		}
	}
	if err := b.UseSandbox(); !errors.Is(err, ErrExhausted) || !strings.Contains(err.Error(), "sandbox run cap") {
		t.Fatalf("sandbox cap: %v", err)
	}
}

func TestCanAffordSkipsWorkThatWouldNotFinish(t *testing.T) {
	b, _ := newBudget(t, caps)
	b.Charge(llm.Usage{InputTokens: 700, CostUSD: 0.5, CostKnown: true})
	if err := b.CanAfford(200, 0.1); err != nil {
		t.Fatal(err)
	}
	if err := b.CanAfford(400, 0.1); !errors.Is(err, ErrExhausted) || !strings.Contains(err.Error(), "300 remain") {
		t.Fatalf("got %v", err)
	}
	if err := b.CanAfford(10, 0.6); !errors.Is(err, ErrExhausted) {
		t.Fatalf("got %v", err)
	}
}

func TestSpentTracksUnknownCost(t *testing.T) {
	b, clock := newBudget(t, caps)
	b.Charge(llm.Usage{InputTokens: 10, OutputTokens: 5, CostUSD: 0.01, CostKnown: true})
	b.Charge(llm.Usage{InputTokens: 20, OutputTokens: 5, CostKnown: false})
	clock.now = clock.now.Add(3 * time.Second)
	s := b.Spent()
	if s.ModelCalls != 2 || s.Tokens() != 40 || s.USD != 0.01 || !s.CostUnknown || s.Elapsed != 3*time.Second {
		t.Fatalf("spent = %+v", s)
	}
}

func TestStagnation(t *testing.T) {
	s := NewStagnation(3)
	if s.Observe("grep", `{"pattern":"a"}`) || s.Observe("grep", `{"pattern":"b"}`) {
		t.Fatal("distinct calls are not repeats")
	}
	for i := 0; i < 2; i++ {
		if !s.Observe("grep", `{"pattern":"a"}`) {
			t.Fatal("an identical call is a repeat")
		}
	}
	if s.Stuck() {
		t.Fatal("two repeats should not trip a limit of three")
	}
	s.Observe("grep", `{"pattern":"b"}`)
	if !s.Stuck() {
		t.Fatal("three repeats should trip")
	}
}
