package cli

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func run(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = Main(args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func TestHelpLeadsWithAuthorizedUse(t *testing.T) {
	code, out, _ := run("help")
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d", code, ExitOK)
	}
	notice := strings.Index(out, "systems you own or have written permission to test")
	cmds := strings.Index(out, "Commands:")
	if notice < 0 || cmds < 0 || notice > cmds {
		t.Fatalf("authorized-use notice must come before the command list:\n%s", out)
	}
}

func TestHelpListsEveryCommand(t *testing.T) {
	_, out, _ := run("--help")
	for _, name := range []string{"scan", "debug", "verify", "report", "doctor", "mcp", "version"} {
		if !strings.Contains(out, "\n  "+name) {
			t.Errorf("help does not list %q", name)
		}
	}
}

func TestNoArgsIsUsageError(t *testing.T) {
	code, out, errOut := run()
	if code != ExitUsage || out != "" || !strings.Contains(errOut, "Usage:") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

func TestUnknownCommandSaysWhatToDo(t *testing.T) {
	code, _, errOut := run("frobnicate")
	if code != ExitUsage || !strings.Contains(errOut, `unknown command "frobnicate"`) || !strings.Contains(errOut, "spackle help") {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := run("version")
	if code != ExitOK || !strings.HasPrefix(out, "spackle ") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestParseInterleaved(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	format := fs.String("format", "", "")
	yes := fs.Bool("yes", false, "")
	pos, err := parseInterleaved(fs, []string{"--yes", "./my app", "--format", "json", "extra"})
	if err != nil {
		t.Fatal(err)
	}
	if !*yes || *format != "json" || len(pos) != 2 || pos[0] != "./my app" || pos[1] != "extra" {
		t.Fatalf("yes=%v format=%q pos=%q", *yes, *format, pos)
	}
}
