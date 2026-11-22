// Package budget enforces the hard caps of a run: tokens, spend, wall
// time, sandbox runs and agent turns. Caps are mandatory. There is no
// "unlimited": an agent loop with no ceiling is how a run costs more than
// the operator meant to spend.
package budget

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/TMHSDigital/spackle/internal/llm"
)

// ErrExhausted is returned (wrapped, naming the cap) when a cap is reached.
var ErrExhausted = errors.New("budget exhausted")

// Caps are the limits of one run. Every field must be positive.
type Caps struct {
	Tokens      int
	USD         float64
	Wall        time.Duration
	SandboxRuns int
}

// Spent is how much of the budget has been used.
type Spent struct {
	InputTokens  int
	OutputTokens int
	USD          float64
	SandboxRuns  int
	ModelCalls   int
	Elapsed      time.Duration
	// CostUnknown is true when any call used a model with no known price,
	// which means the USD cap could not be enforced for that call.
	CostUnknown bool
}

// Tokens is the total of input and output tokens.
func (s Spent) Tokens() int { return s.InputTokens + s.OutputTokens }

// Budget tracks spend against caps. It is safe for concurrent use.
type Budget struct {
	mu    sync.Mutex
	caps  Caps
	spent Spent
	start time.Time
	clock func() time.Time
}

// New starts a budget. clock may be nil for time.Now.
func New(caps Caps, clock func() time.Time) (*Budget, error) {
	if caps.Tokens <= 0 || caps.USD <= 0 || caps.Wall <= 0 || caps.SandboxRuns <= 0 {
		return nil, fmt.Errorf("every budget cap must be positive (tokens %d, usd %.2f, wall %s, sandbox runs %d): caps cannot be turned off", caps.Tokens, caps.USD, caps.Wall, caps.SandboxRuns)
	}
	if clock == nil {
		clock = time.Now
	}
	return &Budget{caps: caps, clock: clock, start: clock()}, nil
}

// Caps returns the configured caps.
func (b *Budget) Caps() Caps { return b.caps }

// Charge records the usage of one model call.
func (b *Budget) Charge(u llm.Usage) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.spent.ModelCalls++
	b.spent.InputTokens += u.InputTokens
	b.spent.OutputTokens += u.OutputTokens
	b.spent.USD += u.CostUSD
	if !u.CostKnown {
		b.spent.CostUnknown = true
	}
}

// Check returns nil while the run may make another model call, and an
// error wrapping ErrExhausted that names the cap otherwise.
func (b *Budget) Check() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.checkLocked()
}

func (b *Budget) checkLocked() error {
	switch {
	case b.spent.Tokens() >= b.caps.Tokens:
		return fmt.Errorf("%w: token cap of %d reached", ErrExhausted, b.caps.Tokens)
	case b.spent.USD >= b.caps.USD:
		return fmt.Errorf("%w: spend cap of $%.2f reached", ErrExhausted, b.caps.USD)
	case b.clock().Sub(b.start) >= b.caps.Wall:
		return fmt.Errorf("%w: wall time cap of %s reached", ErrExhausted, b.caps.Wall)
	}
	return nil
}

// CanAfford reports whether a call estimated at the given size fits in what
// is left. It lets the engine skip a task it could not finish instead of
// starting it and cutting it off.
func (b *Budget) CanAfford(estTokens int, estUSD float64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.checkLocked(); err != nil {
		return err
	}
	if b.spent.Tokens()+estTokens > b.caps.Tokens {
		return fmt.Errorf("%w: about %d tokens are needed and %d remain", ErrExhausted, estTokens, b.caps.Tokens-b.spent.Tokens())
	}
	if b.spent.USD+estUSD > b.caps.USD {
		return fmt.Errorf("%w: about $%.2f is needed and $%.2f remains", ErrExhausted, estUSD, b.caps.USD-b.spent.USD)
	}
	return nil
}

// UseSandbox reserves one sandbox run, or reports that the cap is reached.
func (b *Budget) UseSandbox() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.spent.SandboxRuns >= b.caps.SandboxRuns {
		return fmt.Errorf("%w: sandbox run cap of %d reached", ErrExhausted, b.caps.SandboxRuns)
	}
	if b.clock().Sub(b.start) >= b.caps.Wall {
		return fmt.Errorf("%w: wall time cap of %s reached", ErrExhausted, b.caps.Wall)
	}
	b.spent.SandboxRuns++
	return nil
}

// Remaining returns how long the run may still take.
func (b *Budget) Remaining() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	left := b.caps.Wall - b.clock().Sub(b.start)
	if left < 0 {
		return 0
	}
	return left
}

// Spent returns a snapshot of what has been used.
func (b *Budget) Spent() Spent {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.spent
	s.Elapsed = b.clock().Sub(b.start)
	return s
}

// Stagnation detects an agent that has stopped making progress: it keeps
// issuing tool calls it has already made. It is deliberately simple and
// counts exact repeats, which is how a stuck model actually behaves.
type Stagnation struct {
	seen    map[string]int
	repeats int
	limit   int
}

// NewStagnation returns a detector that trips after limit repeated calls.
func NewStagnation(limit int) *Stagnation {
	if limit <= 0 {
		limit = 4
	}
	return &Stagnation{seen: map[string]int{}, limit: limit}
}

// Observe records a tool call (name plus raw arguments) and reports whether
// it repeats an earlier one.
func (s *Stagnation) Observe(name, args string) (repeat bool) {
	key := name + "\x00" + args
	s.seen[key]++
	if s.seen[key] > 1 {
		s.repeats++
		return true
	}
	return false
}

// Stuck reports whether the repeat limit has been reached.
func (s *Stagnation) Stuck() bool { return s.repeats >= s.limit }
