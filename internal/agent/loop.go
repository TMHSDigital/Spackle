// Package agent holds the model-driven stages of the pipeline: planner,
// investigators, reviewer and the shared tool loop they run on.
//
// The loop gives a model nothing but an allowlisted, read-only tool
// registry. Scope, budgets and tool permissions are enforced here in Go.
// Nothing a model or a target says can change them, because there is no
// tool whose effect is to change them.
package agent

import (
	"context"
	"errors"
	"fmt"

	"github.com/TMHSDigital/spackle/internal/agent/tools"
	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/llm"
	"github.com/TMHSDigital/spackle/internal/redact"
	"github.com/TMHSDigital/spackle/internal/textx"
)

// Runner runs one stage's conversations against a provider.
type Runner struct {
	Provider llm.Provider
	Pricer   llm.Pricer
	Budget   *budget.Budget
	Ledger   *ledger.Writer
	// Stage names the pipeline stage in the ledger: planner, investigator,
	// reviewer, prover, fixer or mechanical.
	Stage string
	// MaxTurns caps tool-use turns in one conversation.
	MaxTurns int
	// MaxTokens caps one completion.
	MaxTokens int
}

// Why a conversation stopped before the model chose to.
const (
	StopNone       = ""
	StopTurns      = "turn limit"
	StopStagnation = "stagnation"
	StopRefusal    = "provider refusal"
	StopTruncated  = "output truncated"
)

// Outcome is the result of one conversation.
type Outcome struct {
	Text    string
	Turns   int
	Stopped string
	// Note explains Stopped when there is more to say (a refusal category).
	Note string
}

const finalAnswerNudge = "Stop using tools now. Using only what you have already seen, give your final answer in the required JSON format. If you could not confirm the issue, say so in the answer."

// Run holds a conversation: it sends system and user, executes any tool
// calls through reg, and returns the model's final text. reg may be nil for
// a conversation with no tools. A budget error is returned as an error
// wrapping budget.ErrExhausted, with whatever was produced so far.
func (r *Runner) Run(ctx context.Context, parent int64, system, user string, reg *tools.Registry) (Outcome, error) {
	maxTurns := r.MaxTurns
	if maxTurns <= 0 {
		maxTurns = 24
	}
	var defs []llm.ToolDef
	if reg != nil {
		defs = reg.Defs()
	}
	msgs := []llm.Message{{Role: llm.RoleUser, Text: user}}
	stag := budget.NewStagnation(4)
	out := Outcome{}

	for {
		req := llm.Request{System: system, Messages: msgs, Tools: defs, MaxTokens: r.MaxTokens}
		resp, seq, err := r.complete(ctx, parent, req)
		if err != nil {
			return out, err
		}
		msgs = append(msgs, resp.AssistantMessage())

		switch resp.StopReason {
		case llm.StopRefusal:
			out.Text, out.Stopped, out.Note = resp.Text, StopRefusal, resp.RefusalNote
			return out, nil
		case llm.StopMaxTokens:
			out.Text, out.Stopped = resp.Text, StopTruncated
			return out, nil
		case llm.StopToolUse:
			// handled below
		default:
			out.Text = resp.Text
			return out, nil
		}
		if reg == nil || len(resp.ToolCalls) == 0 {
			out.Text = resp.Text
			return out, nil
		}

		out.Turns++
		results := make([]llm.ToolResult, 0, len(resp.ToolCalls))
		for _, call := range resp.ToolCalls {
			stag.Observe(call.Name, string(call.Args))
			res := reg.Call(ctx, call)
			results = append(results, res)
			args, _ := redact.Apply(string(call.Args))
			if _, lerr := r.Ledger.Append(seq, ledger.TypeToolCall, ledger.ToolCall{
				Stage: r.Stage, Tool: call.Name, Args: textx.Clip(args, 500), IsError: res.IsError, Bytes: len(res.Content),
			}); lerr != nil {
				return out, lerr
			}
		}
		msgs = append(msgs, llm.Message{Role: llm.RoleTool, ToolResults: results})

		stuck := stag.Stuck()
		if out.Turns >= maxTurns || stuck {
			out.Stopped = StopTurns
			if stuck {
				out.Stopped = StopStagnation
			}
			// One last request, so the work done so far is not thrown
			// away. The tool list stays on it: a provider refuses a
			// conversation that holds tool calls and defines no tools.
			// The nudge asks for an answer; a tool call that comes back
			// anyway is not run, and only the text is kept.
			msgs = append(msgs, llm.Message{Role: llm.RoleUser, Text: finalAnswerNudge})
			final, _, err := r.complete(ctx, parent, llm.Request{System: system, Messages: msgs, Tools: defs, MaxTokens: r.MaxTokens})
			if err != nil {
				return out, err
			}
			out.Text = final.Text
			return out, nil
		}
	}
}

// complete makes one model call with budget checks and ledger accounting.
func (r *Runner) complete(ctx context.Context, parent int64, req llm.Request) (llm.Response, int64, error) {
	if err := ctx.Err(); err != nil {
		return llm.Response{}, 0, err
	}
	if err := r.Budget.Check(); err != nil {
		return llm.Response{}, 0, err
	}
	// The wall time cap is checked before a call starts. Without a
	// deadline, a call that starts just under the cap could run for as
	// long as the provider's client allows. Give it what is left.
	callCtx, cancel := context.WithTimeout(ctx, r.Budget.Remaining())
	resp, err := r.Provider.Complete(callCtx, req)
	overran := err != nil && callCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil
	cancel()
	rec := ledger.ModelCall{Stage: r.Stage, Provider: r.Provider.Name(), Model: r.Provider.Model()}
	if overran {
		err = fmt.Errorf("%w: the wall time cap was reached during a model call, which was stopped", budget.ErrExhausted)
	}
	if err != nil {
		rec.Error = textx.Clip(err.Error(), 300)
		// A failed call is recorded so the ledger shows it happened.
		if _, lerr := r.Ledger.Append(parent, ledger.TypeModelCall, rec); lerr != nil {
			return llm.Response{}, 0, lerr
		}
		var apiErr *llm.APIError
		if errors.As(err, &apiErr) && apiErr.Hint() != "" {
			return llm.Response{}, 0, fmt.Errorf("%w (%s)", err, apiErr.Hint())
		}
		return llm.Response{}, 0, err
	}
	usage := r.Pricer.Cost(r.Provider.Model(), r.Provider.Local(), resp.Usage)
	resp.Usage = usage
	r.Budget.Charge(usage)
	rec.InputTokens, rec.OutputTokens = usage.InputTokens, usage.OutputTokens
	rec.Estimated, rec.CostUSD, rec.CostKnown = usage.Estimated, usage.CostUSD, usage.CostKnown
	seq, lerr := r.Ledger.Append(parent, ledger.TypeModelCall, rec)
	if lerr != nil {
		return llm.Response{}, 0, lerr
	}
	return resp, seq, nil
}
