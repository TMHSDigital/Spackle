package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TMHSDigital/spackle/internal/agent/tools"
	"github.com/TMHSDigital/spackle/internal/envelope"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/seed"
	"github.com/TMHSDigital/spackle/internal/textx"
)

// Investigation is the result of investigating one intent.
type Investigation struct {
	Intent Intent
	// Finding is set when the investigator reported a flaw that passed
	// validation.
	Finding *finding.Finding
	// NoFinding is the investigator's reason when it concluded the lead
	// does not hold up.
	NoFinding string
	// Rejected is why the result could not be used: malformed output, a
	// quote that is not in the file, a refusal, a cut-off answer.
	Rejected string
}

type investigatorReply struct {
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
	Finding *Draft `json:"finding"`
}

// Investigate runs one investigation. A draft that fails validation is sent
// back once with the specific problems; if the second answer also fails,
// the investigation is rejected and recorded, and the run continues.
func Investigate(ctx context.Context, r *Runner, parent int64, root string, sealer *envelope.Sealer, reg *tools.Registry, intent Intent, leads []seed.Lead) (Investigation, error) {
	inv := Investigation{Intent: intent}

	type leadView struct {
		ID, Source, Rule, Title, File string
		Line                          int
		Snippet, Detail               string
	}
	var views []leadView
	for _, l := range leads {
		if containsStr(intent.LeadIDs, l.ID) {
			views = append(views, leadView{l.ID, l.Source, l.RuleID, l.Title, l.File, l.Line, textx.Clip(l.Snippet, 200), textx.Clip(l.Detail, 300)})
		}
	}
	brief := map[string]any{"title": intent.Title, "question": intent.Hypothesis, "start_with_files": intent.Files}
	if intent.Class != "" {
		brief["suspected_class"] = intent.Class
	}
	if len(views) > 0 {
		brief["scanner_leads"] = views
	}
	raw, err := json.MarshalIndent(brief, "", " ")
	if err != nil {
		return inv, err
	}
	user := "Investigate this and answer in the required JSON format.\n\n" + sealer.Wrap("investigation brief", string(raw))

	origin := []string{"investigator:" + intent.ID}
	for _, v := range views {
		origin = append(origin, v.Source+":"+v.Rule)
	}

	system := investigatorSystem(sealer)
	out, err := r.Run(ctx, parent, system, user, reg)
	if err != nil {
		return inv, err
	}

	for attempt := 1; ; attempt++ {
		problem := ""
		switch out.Stopped {
		case StopRefusal:
			inv.Rejected = "the model provider declined this investigation: " + textx.Clip(out.Note, 200)
			return inv, r.reject(parent, intent, inv.Rejected)
		case StopTruncated:
			problem = "the answer was cut off before the JSON was complete"
		}
		var reply investigatorReply
		if problem == "" {
			if derr := decodeReply(out.Text, &reply); derr != nil {
				problem = derr.Error()
			}
		}
		if problem == "" {
			switch strings.ToLower(strings.TrimSpace(reply.Verdict)) {
			case "no_finding":
				inv.NoFinding = textx.Clip(strings.TrimSpace(reply.Reason), 1000)
				if inv.NoFinding == "" {
					inv.NoFinding = "The investigator concluded this is not a flaw and gave no reason."
				}
				return inv, nil
			case "finding":
				if reply.Finding == nil {
					problem = `verdict is "finding" but the finding object is missing`
					break
				}
				f, berr := BuildFinding(root, *reply.Finding, origin)
				if berr == nil {
					inv.Finding = &f
					return inv, nil
				}
				problem = berr.Error()
			default:
				problem = fmt.Sprintf("verdict %q is not finding or no_finding", reply.Verdict)
			}
		}
		if attempt >= 2 {
			inv.Rejected = "the draft was rejected after one correction: " + textx.Clip(problem, 600)
			return inv, r.reject(parent, intent, inv.Rejected)
		}
		// Send the problems back once, so it cannot loop. This is a new
		// conversation that carries the previous answer, with the same
		// tools and the same turn limit as the first attempt: the model may
		// read the files again, so a retry can cost as much as the
		// investigation did.
		retry := "Your previous answer could not be used:\n" + textx.Clip(problem, 1200) +
			"\n\nYour previous answer was:\n" + sealer.Wrap("previous answer", textx.Clip(out.Text, 6000)) +
			"\n\nRe-read the files if you need to, fix those problems, and reply again in the required JSON format. " +
			"If you can no longer support the finding, reply with verdict no_finding.\n\nThe original brief:\n" +
			sealer.Wrap("investigation brief", string(raw))
		out, err = r.Run(ctx, parent, system, retry, reg)
		if err != nil {
			return inv, err
		}
	}
}

func (r *Runner) reject(parent int64, intent Intent, reason string) error {
	_, err := r.Ledger.Append(parent, ledger.TypeReject, ledger.Reject{Stage: r.Stage, Intent: intent.ID + " " + intent.Title, Reason: reason})
	return err
}
