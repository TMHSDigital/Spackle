package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/TMHSDigital/spackle/internal/envelope"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
	"github.com/TMHSDigital/spackle/internal/mapper"
	"github.com/TMHSDigital/spackle/internal/seed"
)

// Intent is one planned investigation.
type Intent = ledger.Intent

// planInput is what the planner sees. It is built by Spackle from the map
// and the leads, then enveloped, because file names, route strings and lead
// snippets all originate in the target.
type planInput struct {
	Languages  []string            `json:"languages"`
	Frameworks []string            `json:"frameworks,omitempty"`
	Entry      []mapper.EntryPoint `json:"entry_points,omitempty"`
	Boundaries map[string][]string `json:"trust_boundaries,omitempty"` // kind -> ["file:line"]
	Infra      []string            `json:"infra_files,omitempty"`
	Leads      []planLead          `json:"leads"`
}

type planLead struct {
	ID      string `json:"id"`
	Source  string `json:"source"`
	Class   string `json:"class"`
	Title   string `json:"title"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet,omitempty"`
}

// Plan asks the model for a prioritized list of investigations. Whatever
// the model returns is validated against the real map and leads: intents
// that name files or leads that do not exist lose those references, and
// intents left with nothing to look at are dropped.
func Plan(ctx context.Context, r *Runner, parent int64, sealer *envelope.Sealer, m mapper.Map, leads []seed.Lead, limit int) ([]Intent, error) {
	in := planInput{Languages: m.LanguageNames(), Frameworks: m.Frameworks, Infra: m.InfraFiles, Boundaries: map[string][]string{}}
	in.Entry = capSlice(m.Entry, 80)
	for _, b := range m.Boundaries {
		if len(in.Boundaries[b.Kind]) < 40 {
			in.Boundaries[b.Kind] = append(in.Boundaries[b.Kind], fmt.Sprintf("%s:%d", b.File, b.Line))
		}
	}
	for _, l := range capSlice(leads, 150) {
		in.Leads = append(in.Leads, planLead{ID: l.ID, Source: l.Source, Class: l.Class, Title: l.Title, File: l.File, Line: l.Line, Snippet: clip(l.Snippet, 160)})
	}
	raw, err := json.MarshalIndent(in, "", " ")
	if err != nil {
		return nil, err
	}
	user := fmt.Sprintf("Plan at most %d investigations for this target.\n\n%s", limit, sealer.Wrap("target map and leads", string(raw)))

	out, err := r.Run(ctx, parent, plannerSystem(sealer), user, nil)
	if err != nil {
		return nil, err
	}
	var reply struct {
		Intents []Intent `json:"intents"`
	}
	if err := decodeReply(out.Text, &reply); err != nil {
		return nil, fmt.Errorf("planner: %w", err)
	}
	return validateIntents(reply.Intents, m, leads, limit, "planner"), nil
}

func validateIntents(in []Intent, m mapper.Map, leads []seed.Lead, limit int, source string) []Intent {
	files := map[string]bool{}
	for _, f := range m.Files {
		files[f.Rel] = true
	}
	leadByID := map[string]seed.Lead{}
	for _, l := range leads {
		leadByID[l.ID] = l
	}
	var out []Intent
	for _, it := range in {
		it.Title = clip(strings.TrimSpace(it.Title), 160)
		it.Hypothesis = clip(strings.TrimSpace(it.Hypothesis), 600)
		if it.Title == "" && it.Hypothesis == "" {
			continue
		}
		if _, ok := finding.DefaultVector(it.Class); !ok {
			it.Class = ""
		}
		var keptFiles []string
		for _, f := range it.Files {
			f = strings.TrimPrefix(strings.ReplaceAll(f, `\`, "/"), "./")
			if files[f] {
				keptFiles = append(keptFiles, f)
			}
		}
		var keptLeads []string
		for _, id := range it.LeadIDs {
			if l, ok := leadByID[id]; ok {
				keptLeads = append(keptLeads, id)
				if l.File != "" && files[l.File] && !containsStr(keptFiles, l.File) {
					keptFiles = append(keptFiles, l.File)
				}
			}
		}
		if len(keptFiles) == 0 {
			continue // nothing real to look at
		}
		it.Files, it.LeadIDs = capSlice(keptFiles, 8), keptLeads
		if it.Priority < 1 || it.Priority > 5 {
			it.Priority = 3
		}
		it.Source = source
		out = append(out, it)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	out = capSlice(out, limit)
	for i := range out {
		out[i].ID = fmt.Sprintf("I-%02d", i+1)
	}
	return out
}

// FallbackPlan builds intents straight from leads, one per file and class,
// worst severity first. It is used when the planner fails or returns
// nothing usable, so a model problem degrades the run instead of ending it.
func FallbackPlan(m mapper.Map, leads []seed.Lead, limit int) []Intent {
	type key struct{ file, class string }
	groups := map[key]*Intent{}
	var order []key
	rank := map[string]int{"critical": 1, "high": 2, "medium": 3, "low": 4}
	for _, l := range leads {
		if l.File == "" {
			continue
		}
		k := key{l.File, l.Class}
		g, ok := groups[k]
		if !ok {
			pr := rank[strings.ToLower(l.Severity)]
			if pr == 0 {
				pr = 3
			}
			g = &Intent{
				Title: l.Title, Class: l.Class, Priority: pr, Files: []string{l.File},
				Hypothesis: fmt.Sprintf("A scanner reported %q at %s:%d. Is it a real flaw that an attacker can reach, and what is its impact?", l.Title, l.File, l.Line),
			}
			groups[k] = g
			order = append(order, k)
		}
		g.LeadIDs = append(g.LeadIDs, l.ID)
	}
	intents := make([]Intent, 0, len(order))
	for _, k := range order {
		intents = append(intents, *groups[k])
	}
	return validateIntents(intents, m, leads, limit, "fallback")
}

func capSlice[T any](s []T, n int) []T {
	if n >= 0 && len(s) > n {
		return s[:n]
	}
	return s
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
