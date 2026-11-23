package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TMHSDigital/spackle/internal/agent/tools"
	"github.com/TMHSDigital/spackle/internal/envelope"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/textx"
)

// Review verdicts.
const (
	ReviewConfirmed = "confirmed"
	ReviewRefuted   = "refuted"
	ReviewUncertain = "uncertain"
)

// Review is the reviewer's verdict on one finding.
type Review struct {
	Verdict string
	Reason  string
	// Severity is set when the reviewer supplied a valid corrected vector.
	Severity *finding.Severity
}

// claim is what the reviewer is shown: the finding's assertions, without
// the investigator's reasoning or confidence. Fresh context is the point of
// the review, so nothing that would anchor the reviewer is included.
type claim struct {
	Title       string             `json:"title"`
	Class       string             `json:"class"`
	Location    string             `json:"location"`
	Description string             `json:"description"`
	Flow        []finding.FlowStep `json:"flow"`
	AttackSteps []string           `json:"attack_steps,omitempty"`
	Severity    string             `json:"cvss_vector"`
}

// ReviewFinding runs the adversarial review of one finding in a fresh
// conversation with its own tool registry.
func ReviewFinding(ctx context.Context, r *Runner, parent int64, sealer *envelope.Sealer, reg *tools.Registry, f finding.Finding) (Review, error) {
	c := claim{
		Title: f.Title, Class: f.Class, Location: f.Location.String(), Description: f.Flaw.Description,
		Flow: f.Flaw.Flow, AttackSteps: f.Exploitation.Steps, Severity: f.Severity.Vector,
	}
	raw, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		return Review{}, err
	}
	user := "Try to refute this finding by reading the code, then give your verdict in the required JSON format.\n\n" +
		sealer.Wrap("finding under review", string(raw))
	out, err := r.Run(ctx, parent, reviewerSystem(sealer), user, reg)
	if err != nil {
		return Review{}, err
	}
	if out.Stopped == StopRefusal || out.Stopped == StopTruncated {
		return Review{Verdict: ReviewUncertain, Reason: "The review did not complete (" + out.Stopped + "), so the finding was neither confirmed nor refuted."}, nil
	}
	var reply struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
		Vector  string `json:"cvss_vector"`
	}
	if err := decodeReply(out.Text, &reply); err != nil {
		// An unusable review must not confirm or dismiss anything, and it
		// must not fail the run either: it becomes an "uncertain" verdict.
		//nolint:nilerr // the parse failure is reported in the verdict's reason
		return Review{Verdict: ReviewUncertain, Reason: "The reviewer's answer could not be parsed (" + err.Error() + "), so the finding was neither confirmed nor refuted."}, nil
	}
	rev := Review{Reason: textx.Clip(strings.TrimSpace(reply.Reason), 1200)}
	switch strings.ToLower(strings.TrimSpace(reply.Verdict)) {
	case ReviewConfirmed:
		rev.Verdict = ReviewConfirmed
	case ReviewRefuted:
		rev.Verdict = ReviewRefuted
		if rev.Reason == "" {
			// A dismissal needs a reason the operator can check. Without
			// one, keep the finding.
			rev.Verdict = ReviewUncertain
			rev.Reason = "The reviewer said the finding was refuted but gave no reason, so it was kept."
		}
	default:
		rev.Verdict = ReviewUncertain
	}
	if rev.Reason == "" {
		rev.Reason = "The reviewer gave no reason."
	}
	if v := strings.TrimSpace(reply.Vector); v != "" && v != f.Severity.Vector {
		if sev, serr := finding.SeverityFromVector(v, fmt.Sprintf("Adjusted by review. %s", rev.Reason)); serr == nil {
			rev.Severity = &sev
		}
	}
	return rev, nil
}

// ApplyReview returns the finding updated with the review's outcome.
//   - confirmed: unchanged, apart from a corrected severity.
//   - refuted: dismissed, with the reviewer's reason kept.
//   - uncertain: kept open, but confidence drops to plausible, because a
//     second reader could not verify it.
func ApplyReview(f finding.Finding, rev Review) finding.Finding {
	if rev.Severity != nil {
		f.Severity = *rev.Severity
	}
	switch rev.Verdict {
	case ReviewRefuted:
		f.Status = finding.StatusDismissed
		f.DismissReason = rev.Reason
	case ReviewUncertain:
		if f.Confidence.Level == finding.ConfidenceHigh {
			f.Confidence.Level = finding.ConfidencePlausible
			f.Confidence.Reason = strings.TrimSpace(f.Confidence.Reason + " Review could not confirm it: " + rev.Reason)
		}
	case ReviewConfirmed:
		f.Confidence.Reason = strings.TrimSpace(f.Confidence.Reason + " Confirmed by an independent review.")
	}
	return f
}

// Correlate asks the model which confirmed findings combine into a larger
// attack and returns the findings with their kill chain and related ids
// filled in. Chains that name unknown ids are ignored. A failure here is not
// fatal: the findings are returned unchanged with the error.
func Correlate(ctx context.Context, r *Runner, parent int64, sealer *envelope.Sealer, fs []finding.Finding) ([]finding.Finding, error) {
	type row struct {
		ID       string   `json:"id"`
		Title    string   `json:"title"`
		Class    string   `json:"class"`
		Location string   `json:"location"`
		Gains    []string `json:"gains,omitempty"`
		Needs    []string `json:"preconditions,omitempty"`
	}
	var rows []row
	index := map[string]int{}
	for i, f := range fs {
		if f.Status != finding.StatusOpen {
			continue
		}
		index[f.ID] = i
		rows = append(rows, row{f.ID, f.Title, f.Class, f.Location.String(), f.BlastRadius.Gains, f.Exploitation.Preconditions})
	}
	if len(rows) < 2 {
		return fs, nil
	}
	raw, err := json.MarshalIndent(capSlice(rows, 60), "", " ")
	if err != nil {
		return fs, err
	}
	out, err := r.Run(ctx, parent, correlateSystem(sealer), "Which of these findings combine?\n\n"+sealer.Wrap("findings", string(raw)), nil)
	if err != nil {
		return fs, err
	}
	var reply struct {
		Chains []struct {
			IDs       []string `json:"ids"`
			Narrative string   `json:"narrative"`
		} `json:"chains"`
	}
	if err := decodeReply(out.Text, &reply); err != nil {
		return fs, fmt.Errorf("correlate: %w", err)
	}
	res := make([]finding.Finding, len(fs))
	copy(res, fs)
	for _, ch := range reply.Chains {
		var ids []string
		for _, id := range ch.IDs {
			if _, ok := index[id]; ok && !containsStr(ids, id) {
				ids = append(ids, id)
			}
		}
		narrative := textx.Clip(strings.TrimSpace(ch.Narrative), 800)
		if len(ids) < 2 || narrative == "" {
			continue
		}
		for _, id := range ids {
			f := &res[index[id]]
			if f.BlastRadius.KillChain == "" {
				f.BlastRadius.KillChain = narrative
			}
			for _, other := range ids {
				if other != id && !containsStr(f.BlastRadius.Related, other) {
					f.BlastRadius.Related = append(f.BlastRadius.Related, other)
				}
			}
		}
	}
	return res, nil
}
