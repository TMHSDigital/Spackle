// Package cli implements the spackle command line: subcommand dispatch,
// flag parsing, help text and exit codes.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/TMHSDigital/spackle/internal/version"
)

// Exit codes. They are part of the CLI contract (see docs/ci.md).
const (
	ExitOK       = 0 // ran, nothing at or above the failure threshold
	ExitFindings = 1 // ran, findings at or above the failure threshold
	ExitUsage    = 2 // bad flags, bad config, or a refused target
	ExitError    = 3 // the run itself failed
)

// AuthorizedUse is shown at the top of help output and in the README.
const AuthorizedUse = "Authorized use only. Point Spackle at systems you own or have written permission to test."

// Env carries the process streams so commands are testable.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// command is one subcommand.
type command struct {
	name    string
	args    string
	summary string
	run     func(env Env, args []string) int
}

func commands() []command {
	return []command{
		{"scan", "[path|url]", "Find, demonstrate, explain and fix flaws in a target", runScan},
		{"debug", "[path] --test <name> | --issue <file|text>", "Reproduce a failure, find the root cause, fix and verify", runDebug},
		{"verify", "<run-id>", "Re-run stored proofs against the current target", runVerify},
		{"report", "<run-id>", "Render a stored run in any format", runReport},
		{"runs", "[prune|compare]", "List stored runs, delete old ones, or compare two", runRuns},
		{"baseline", "[run-id]", "Write a baseline file that accepts the findings of a stored run", runBaseline},
		{"rules", "", "List the built-in rules that [scan] disable_rules can name", runRules},
		{"doctor", "", "Check the sandbox runtime, scanners and model configuration", runDoctor},
		{"mcp", "", "Serve Spackle tools over MCP on stdin and stdout", runMCP},
		{"version", "", "Print version information", runVersion},
	}
}

// Main runs the CLI and returns the process exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	env := Env{Stdin: stdin, Stdout: stdout, Stderr: stderr}
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		usage(stdout)
		return ExitOK
	case "-v", "--version":
		return runVersion(env, nil)
	}
	// bench is a maintainer tool reached through "make bench". It is kept
	// out of commands() so it does not appear in the user-facing help.
	if args[0] == "bench" {
		return runBench(env, args[1:])
	}
	for _, c := range commands() {
		if c.name == args[0] {
			return c.run(env, args[1:])
		}
	}
	fmt.Fprintf(stderr, "spackle: unknown command %q.\nRun \"spackle help\" to list commands.\n", args[0])
	return ExitUsage
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "%s\n\n", AuthorizedUse)
	fmt.Fprintln(w, "Spackle finds real flaws, proves them, explains how they would be exploited, and fixes them.")
	fmt.Fprint(w, "\nUsage:\n  spackle <command> [flags] [arguments]\n\nCommands:\n")
	cmds := commands()
	width := 0
	for _, c := range cmds {
		if n := len(c.name); n > width {
			width = n
		}
	}
	for _, c := range cmds {
		fmt.Fprintf(w, "  %-*s  %s\n", width, c.name, c.summary)
	}
	fmt.Fprintln(w, "\nRun \"spackle <command> --help\" for the flags of one command.")
	fmt.Fprintln(w, "Live hosts and URLs require an authorized scope: see \"spackle scan --help\".")
}

func runVersion(env Env, _ []string) int {
	fmt.Fprintf(env.Stdout, "spackle %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
	return ExitOK
}

// parseInterleaved parses flags that may appear before, between or after
// positional arguments, which the standard flag package does not allow.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// newFlagSet builds a FlagSet whose help output leads with the
// authorized-use notice and lists flags in a stable order.
func newFlagSet(env Env, name, args, summary string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() {
		w := fs.Output()
		fmt.Fprintf(w, "%s\n\n%s\n\nUsage:\n  spackle %s %s\n\nFlags:\n", AuthorizedUse, summary, name, strings.TrimSpace("[flags] "+args))
		var lines []string
		fs.VisitAll(func(f *flag.Flag) {
			typ, usage := flag.UnquoteUsage(f)
			head := "  --" + f.Name
			if typ != "" {
				head += " " + typ
			}
			line := fmt.Sprintf("%-28s %s", head, usage)
			if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
				line += fmt.Sprintf(" (default %s)", f.DefValue)
			}
			lines = append(lines, line)
		})
		sort.Strings(lines)
		fmt.Fprintln(w, strings.Join(lines, "\n"))
	}
	return fs
}

// flagExit maps a flag parsing error to an exit code. Asking for help is
// not an error.
func flagExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	return ExitUsage
}
