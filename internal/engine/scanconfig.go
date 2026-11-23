package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/seed"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// walkOptions turns the [scan] table into the listing options.
func walkOptions(cfg config.Config) walk.Options {
	return walk.Options{Exclude: cfg.Scan.Exclude, Include: cfg.Scan.Include}
}

// applyScanConfig drops the leads the [scan] table switches off: leads in an
// excluded path (an external scanner reads the tree itself, so its leads are
// filtered here) and leads of a disabled rule. The notes say what was
// configured and how much it removed, so the report shows what the scan did
// not cover.
func applyScanConfig(leads []seed.Lead, sc config.Scan) ([]seed.Lead, []string) {
	if len(sc.Exclude) == 0 && len(sc.Include) == 0 && len(sc.DisableRules) == 0 {
		return leads, nil
	}
	disabled := map[string]bool{}
	for _, r := range sc.DisableRules {
		disabled[strings.TrimSpace(r)] = true
	}
	byRule := map[string]int{}
	excluded := 0
	kept := leads[:0:0]
	for _, l := range leads {
		switch {
		case l.File != "" && walk.Match(sc.Exclude, l.File):
			excluded++
		case disabled[l.RuleID] || disabled[l.Source+":"+l.RuleID]:
			byRule[l.RuleID]++
		default:
			kept = append(kept, l)
		}
	}
	var notes []string
	if len(sc.Exclude) > 0 {
		notes = append(notes, fmt.Sprintf("Excluded by configuration: %s (%d scanner leads dropped)", strings.Join(sc.Exclude, ", "), excluded))
	}
	if len(sc.Include) > 0 {
		notes = append(notes, "Included by configuration although skipped by default: "+strings.Join(sc.Include, ", "))
	}
	if len(sc.DisableRules) > 0 {
		rules := append([]string(nil), sc.DisableRules...)
		sort.Strings(rules)
		parts := make([]string, 0, len(rules))
		for _, r := range rules {
			n := byRule[r]
			if i := strings.LastIndex(r, ":"); n == 0 && i >= 0 {
				n = byRule[r[i+1:]]
			}
			parts = append(parts, fmt.Sprintf("%s (%d leads dropped)", r, n))
		}
		notes = append(notes, "Rules disabled by configuration: "+strings.Join(parts, ", "))
	}
	return kept, notes
}
