package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scanOnce stores one deterministic run in a fresh state directory and
// returns the config file that names it.
func runsFixture(t *testing.T, scans int) (cfg, state string) {
	t.Helper()
	dir := t.TempDir()
	state = filepath.Join(dir, "state")
	cfg = filepath.Join(dir, "spackle.toml")
	body := "state_dir = " + "'" + state + "'" + "\n[sandbox]\nruntime = \"none\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "app")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "app.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < scans; i++ {
		var out, errb bytes.Buffer
		if code := Main([]string{"scan", target, "--config", cfg, "--fail-on", "never"}, strings.NewReader(""), &out, &errb); code != ExitOK {
			t.Fatalf("scan exited %d: %s", code, errb.String())
		}
	}
	return cfg, state
}

func runsIn(t *testing.T, state string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(state, "runs"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestRunsListsStoredRuns(t *testing.T) {
	cfg, state := runsFixture(t, 2)
	names := runsIn(t, state)
	if len(names) != 2 {
		t.Fatalf("stored runs = %v", names)
	}
	var out, errb bytes.Buffer
	if code := Main([]string{"runs", "--config", cfg}, strings.NewReader(""), &out, &errb); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	for _, n := range names {
		if !strings.Contains(out.String(), n) {
			t.Errorf("the list does not name run %s:\n%s", n, out.String())
		}
	}
	if !strings.Contains(out.String(), "2 run(s)") || !strings.Contains(out.String(), "completed") {
		t.Errorf("list = %s", out.String())
	}
	out.Reset()
	if code := Main([]string{"runs", "--config", cfg, "--format", "json"}, strings.NewReader(""), &out, &errb); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var got struct {
		Runs []struct {
			RunID   string `json:"run_id"`
			Outcome string `json:"outcome"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || len(got.Runs) != 2 || got.Runs[0].RunID < got.Runs[1].RunID {
		t.Fatalf("json = %s (%v); want two runs, newest first", out.String(), err)
	}
}

func TestRunsPrune(t *testing.T) {
	cfg, state := runsFixture(t, 3)
	names := runsIn(t, state)
	oldest := names[0]
	// The oldest run has a clone and a fix worktree in the state directory.
	for _, extra := range []string{"clones", "worktrees"} {
		if err := os.MkdirAll(filepath.Join(state, extra, oldest, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var out, errb bytes.Buffer
	// Without a rule, and without consent, nothing is deleted.
	if code := Main([]string{"runs", "prune", "--config", cfg}, strings.NewReader(""), &out, &errb); code != ExitUsage {
		t.Fatalf("prune with no rule exited %d", code)
	}
	if code := Main([]string{"runs", "prune", "--config", cfg, "--keep", "1"}, strings.NewReader("y\n"), &out, &errb); code != ExitUsage {
		t.Fatalf("prune without --yes and without a terminal exited %d", code)
	}
	if got := runsIn(t, state); len(got) != 3 {
		t.Fatalf("runs were deleted without consent: %v", got)
	}
	if code := Main([]string{"runs", "prune", "--config", cfg, "--keep", "1", "extra"}, strings.NewReader(""), &out, &errb); code != ExitUsage {
		t.Fatalf("prune with a name exited %d", code)
	}
	out.Reset()
	if code := Main([]string{"runs", "prune", "--config", cfg, "--keep", "1", "--yes"}, strings.NewReader(""), &out, &errb); code != ExitOK {
		t.Fatalf("prune exited %d: %s", code, errb.String())
	}
	left := runsIn(t, state)
	if len(left) != 1 || left[0] != names[2] {
		t.Fatalf("left = %v, want only the newest run %s", left, names[2])
	}
	for _, extra := range []string{"clones", "worktrees"} {
		if _, err := os.Stat(filepath.Join(state, extra, oldest)); err == nil {
			t.Errorf("the %s of the pruned run were left behind", extra)
		}
	}
	if !strings.Contains(out.String(), "Deleted 2 run(s)") {
		t.Errorf("output = %s", out.String())
	}
	// Nothing selected: nothing to do, and that is not an error.
	out.Reset()
	if code := Main([]string{"runs", "prune", "--config", cfg, "--older-than", "30d", "--yes"}, strings.NewReader(""), &out, &errb); code != ExitOK || !strings.Contains(out.String(), "Nothing to delete") {
		t.Fatalf("exit %d, output %s", code, out.String())
	}
	if code := Main([]string{"runs", "prune", "--config", cfg, "--older-than", "soon"}, strings.NewReader(""), &out, &errb); code != ExitUsage {
		t.Fatalf("a bad age exited %d", code)
	}
}

func TestRunsCompare(t *testing.T) {
	cfg, state := runsFixture(t, 0)
	target := filepath.Join(filepath.Dir(cfg), "app")
	scan := func() {
		t.Helper()
		var out, errb bytes.Buffer
		if code := Main([]string{"scan", target, "--config", cfg, "--fail-on", "never"}, strings.NewReader(""), &out, &errb); code != ExitOK {
			t.Fatalf("scan exited %d: %s", code, errb.String())
		}
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(target, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Older run: one flaw in a.py. Newer run: that flaw is gone, another
	// stays, and a new one appears in c.py.
	write("a.py", "import subprocess\n\ndef run(cmd):\n    return subprocess.run(\"sh -c \" + cmd, shell=True)\n")
	write("b.py", "import hashlib\n\ndef digest(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n")
	scan()
	write("a.py", "def run(cmd):\n    return None\n")
	write("c.py", "import yaml\n\ndef load(f):\n    return yaml.load(f)\n")
	scan()
	names := runsIn(t, state)
	if len(names) != 2 {
		t.Fatalf("runs = %v", names)
	}
	var out, errb bytes.Buffer
	if code := Main([]string{"runs", "compare", names[0], names[1], "--config", cfg, "--format", "json"}, strings.NewReader(""), &out, &errb); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var got struct {
		Older, Newer string
		New          []struct{ Location string }
		Gone         []struct{ Location string }
		StillPresent []struct{ Location string } `json:"still_present"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	where := func(rows []struct{ Location string }) string {
		var files []string
		for _, r := range rows {
			files = append(files, strings.SplitN(r.Location, ":", 2)[0])
		}
		return strings.Join(files, ",")
	}
	if got.Older != names[0] || got.Newer != names[1] || where(got.New) != "c.py" || where(got.Gone) != "a.py" || where(got.StillPresent) != "b.py" {
		t.Fatalf("new=%q gone=%q still=%q\n%s", where(got.New), where(got.Gone), where(got.StillPresent), out.String())
	}
	out.Reset()
	if code := Main([]string{"runs", "compare", names[0], "latest", "--config", cfg}, strings.NewReader(""), &out, &errb); code != ExitOK || !strings.Contains(out.String(), "New: 1") || !strings.Contains(out.String(), "Gone: 1") || !strings.Contains(out.String(), "Still present: 1") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if code := Main([]string{"runs", "compare", names[0], "--config", cfg}, strings.NewReader(""), &out, &errb); code != ExitUsage {
		t.Fatalf("one run id exited %d", code)
	}
}
