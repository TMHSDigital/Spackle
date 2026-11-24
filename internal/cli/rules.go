package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/TMHSDigital/spackle/internal/seed"
)

func runRules(env Env, args []string) int {
	fs := newFlagSet(env, "rules", "", "List the built-in rules: their source, id, class, severity, CWE and the files they read.\nAn id, or source:id, is what [scan] disable_rules takes.\nRules of external scanners (semgrep, gitleaks, ...) are not listed: see each scanner's own documentation.")
	format := fs.String("format", "text", "`text` or json")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return flagExit(err)
	}
	if len(pos) > 0 {
		fmt.Fprintf(env.Stderr, "spackle rules: unexpected argument %q\n", pos[0])
		return ExitUsage
	}
	rules := seed.BuiltinRules()
	switch *format {
	case "json":
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(struct {
			Rules []seed.RuleInfo `json:"rules"`
		}{rules}); err != nil {
			fmt.Fprintf(env.Stderr, "spackle rules: %v\n", err)
			return ExitError
		}
	case "text":
		tw := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SOURCE\tID\tCLASS\tSEVERITY\tCWE\tFILES")
		for _, r := range rules {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Source, r.ID, r.Class, r.Severity, r.CWE, strings.Join(r.Langs, ","))
		}
		if err := tw.Flush(); err != nil {
			return ExitError
		}
		fmt.Fprintf(env.Stdout, "\n%d built-in rules.\n", len(rules))
	default:
		fmt.Fprintf(env.Stderr, "spackle rules: --format %q is not text or json\n", *format)
		return ExitUsage
	}
	return ExitOK
}
