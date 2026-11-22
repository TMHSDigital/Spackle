package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TMHSDigital/spackle/internal/agent/tools"
	"github.com/TMHSDigital/spackle/internal/envelope"
	"github.com/TMHSDigital/spackle/internal/finding"
)

// EndpointReview is an investigator's assessment of one running-target
// finding.
type EndpointReview struct {
	// Confirmed is false when the investigator concluded the observation is
	// not a real flaw; Reason then says why.
	Confirmed bool
	Reason    string
	Finding   finding.Finding
	// Rejected is set when the answer could not be used. The finding is
	// then left as the probe reported it.
	Rejected string
}

func endpointSystem(s *envelope.Sealer) string {
	return roleFrame + "\n\n" + s.Preamble() + "\n\n" + honestyRules + `

Your job in this step is to assess one observation that a probe made against the operator's own
running application, inside a scope the operator authorized. You are given the observation and
the recorded request and response that produced it. You may send a small number of further
requests with the http_request tool to confirm or rule it out. The tool only reaches hosts and
paths inside the authorized scope and only the methods the operator allowed; anything else is
refused, and that is not something to work around.

Stay within what a careful tester does on a system they were asked to assess: read-only requests,
harmless marker values, no attempts to delete or change data, no credential guessing, no
load. If confirming the issue would require something destructive, say so and stop.

Reply with one JSON object and nothing else:
{"verdict":"confirmed|not_confirmed","reason":"what you checked and what came back",
 "title":"specific, names the endpoint and parameter",
 "cvss_vector":"a complete CVSS 4.0 base vector for this instance",
 "severity_reasoning":"why",
 "description":"what is wrong, in two to four sentences",
 "preconditions":["..."],"attack_steps":["which request, which parameter, what comes back"],
 "chains_into":["..."],"gains":["..."],"exposed":["..."],
 "fix_summary":"the specific change to make on the server","fix_why":"why it closes the flaw",
 "defense_in_depth":["..."],
 "evidence":["X-0003"]}
"evidence" lists the ids of the recorded exchanges that show the flaw; use only ids you were given
or that the tool returned. For "not_confirmed", only verdict and reason are needed.`
}

type endpointReply struct {
	Verdict           string   `json:"verdict"`
	Reason            string   `json:"reason"`
	Title             string   `json:"title"`
	Vector            string   `json:"cvss_vector"`
	SeverityReasoning string   `json:"severity_reasoning"`
	Description       string   `json:"description"`
	Preconditions     []string `json:"preconditions"`
	AttackSteps       []string `json:"attack_steps"`
	ChainsInto        []string `json:"chains_into"`
	Gains             []string `json:"gains"`
	Exposed           []string `json:"exposed"`
	FixSummary        string   `json:"fix_summary"`
	FixWhy            string   `json:"fix_why"`
	DefenseInDepth    []string `json:"defense_in_depth"`
	Evidence          []string `json:"evidence"`
}

// InvestigateEndpoint asks the model to confirm and explain one
// running-target finding. exchanges are the recorded request and response
// pairs that produced it, already redacted, as text. known reports whether
// an exchange id exists, so the model cannot cite evidence that was never
// recorded.
func InvestigateEndpoint(ctx context.Context, r *Runner, parent int64, sealer *envelope.Sealer, reg *tools.Registry, f finding.Finding, exchanges string, known func(id string) bool) (EndpointReview, error) {
	rev := EndpointReview{Finding: f}
	brief := map[string]any{
		"observation": f.Title, "class": f.Class, "location": f.Location.String(),
		"detail": f.Flaw.Description, "evidence_ids": f.Proof.Artifacts,
	}
	raw, err := json.MarshalIndent(brief, "", " ")
	if err != nil {
		return rev, err
	}
	user := "Assess this observation.\n\n" + sealer.Wrap("observation", string(raw)) + "\n\n" + sealer.Wrap("recorded exchanges", clip(exchanges, 12000))
	out, err := r.Run(ctx, parent, endpointSystem(sealer), user, reg)
	if err != nil {
		return rev, err
	}
	if out.Stopped == StopRefusal || out.Stopped == StopTruncated {
		rev.Rejected = "the model did not complete the assessment (" + out.Stopped + ")"
		return rev, nil
	}
	var reply endpointReply
	if derr := decodeReply(out.Text, &reply); derr != nil {
		rev.Rejected = derr.Error()
		return rev, nil
	}
	switch strings.ToLower(strings.TrimSpace(reply.Verdict)) {
	case "not_confirmed":
		rev.Reason = clip(strings.TrimSpace(reply.Reason), 1000)
		if rev.Reason == "" {
			rev.Rejected = "the model said the observation was not confirmed but gave no reason"
		}
		return rev, nil
	case "confirmed":
	default:
		rev.Rejected = fmt.Sprintf("verdict %q is not confirmed or not_confirmed", reply.Verdict)
		return rev, nil
	}
	rev.Confirmed = true
	rev.Reason = clip(strings.TrimSpace(reply.Reason), 1000)

	g := f
	if t := strings.TrimSpace(reply.Title); t != "" {
		g.Title = clip(t, 200)
	}
	if d := strings.TrimSpace(reply.Description); d != "" {
		g.Flaw.Description = clip(d, 2000)
	}
	// The score is computed from the vector. An invalid vector leaves the
	// severity the probe assigned.
	if sev, serr := finding.SeverityFromVector(reply.Vector, clip(reply.SeverityReasoning, 800)); serr == nil {
		g.Severity = sev
	}
	g.Exploitation = finding.Exploitation{
		Preconditions: clipAll(reply.Preconditions, 8, 400),
		Steps:         clipAll(reply.AttackSteps, 12, 600),
		ChainsInto:    clipAll(reply.ChainsInto, 6, 400),
	}
	g.BlastRadius.Gains = clipAll(reply.Gains, 8, 400)
	g.BlastRadius.Exposed = clipAll(reply.Exposed, 8, 400)
	if s := strings.TrimSpace(reply.FixSummary); s != "" {
		g.Remediation.Summary = clip(s, 1200)
	}
	g.Remediation.Why = clip(reply.FixWhy, 1200)
	g.Remediation.DefenseInDepth = clipAll(reply.DefenseInDepth, 6, 400)
	// Keep only evidence that was really recorded.
	for _, id := range reply.Evidence {
		id = strings.TrimSpace(id)
		ref := "evidence/exchanges/" + id + ".json"
		if known(id) && !containsStr(g.Proof.Artifacts, ref) {
			g.Proof.Artifacts = append(g.Proof.Artifacts, ref)
		}
	}
	g.Origin = append(g.Origin, "investigator:endpoint")
	if verr := g.Validate(); verr != nil {
		rev.Confirmed = false
		rev.Rejected = "the assessment produced an invalid finding: " + clip(verr.Error(), 300)
		return rev, nil
	}
	rev.Finding = g
	return rev, nil
}
