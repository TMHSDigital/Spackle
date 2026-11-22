package diffx

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEqualContentHasNoDiff(t *testing.T) {
	if d := Unified("a.py", "x\n", "x\n"); d != "" {
		t.Fatalf("got %q", d)
	}
}

func TestSimpleChange(t *testing.T) {
	before := "one\ntwo\nthree\n"
	after := "one\nTWO\nthree\n"
	want := "diff --git a/app/db.py b/app/db.py\n--- a/app/db.py\n+++ b/app/db.py\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n"
	if got := Unified("app/db.py", before, after); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if a, r := Stat(want); a != 1 || r != 1 {
		t.Fatalf("stat = +%d -%d", a, r)
	}
}

func TestDistantChangesMakeSeparateHunks(t *testing.T) {
	var lines []string
	for i := 1; i <= 40; i++ {
		lines = append(lines, fmt.Sprintf("line %d", i))
	}
	before := strings.Join(lines, "\n") + "\n"
	lines[2] = "changed 3"
	lines[35] = "changed 36"
	after := strings.Join(lines, "\n") + "\n"
	d := Unified("f.txt", before, after)
	if n := strings.Count(d, "\n@@ "); n != 2 {
		t.Fatalf("hunks = %d, want 2:\n%s", n, d)
	}
	if !strings.Contains(d, "@@ -1,6 +1,6 @@") || !strings.Contains(d, "@@ -33,7 +33,7 @@") {
		t.Fatalf("unexpected hunk headers:\n%s", d)
	}
}

// applyCases are checked by round-tripping through git apply, which is the
// tool that will consume these patches.
var applyCases = map[string][2]string{
	"change in the middle":      {"a\nb\nc\nd\ne\nf\ng\nh\n", "a\nb\nc\nX\ne\nf\ng\nh\n"},
	"insert at start":           {"a\nb\n", "new\na\nb\n"},
	"append at end":             {"a\nb\n", "a\nb\nnew\n"},
	"delete lines":              {"a\nb\nc\nd\n", "a\nd\n"},
	"no trailing newline after": {"a\nb\n", "a\nb\nc"},
	"no trailing newline both":  {"a\nb", "a\nB"},
	"add trailing newline":      {"a\nb", "a\nb\n"},
	"new file":                  {"", "hello\nworld\n"},
	"whole file replaced":       {"x\ny\nz\n", "1\n2\n3\n4\n"},
	"repeated lines":            {"a\na\na\nb\na\na\n", "a\na\nb\nb\na\n"},
	"indentation and tabs":      {"def f():\n    return 1\n", "def f():\n\tif x:\n\t\treturn 2\n    return 1\n"},
	"two far apart changes":     {strings.Repeat("l\n", 30) + "end\n", "start\n" + strings.Repeat("l\n", 30) + "END\n"},
}

func TestPatchesApplyWithGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed; skipping the git apply round trip")
	}
	for name, tc := range applyCases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "src", "f.txt")
			if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
				t.Fatal(err)
			}
			if tc[0] != "" {
				if err := os.WriteFile(file, []byte(tc[0]), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			patch := Unified("src/f.txt", tc[0], tc[1])
			pf := filepath.Join(t.TempDir(), "p.patch")
			if err := os.WriteFile(pf, []byte(patch), 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("git", "-c", "core.autocrlf=false", "apply", "--whitespace=nowarn", pf)
			cmd.Dir = dir
			// If the temp directory sits inside some git repository, git
			// apply resolves paths against that repository and silently
			// skips files outside it. The ceiling makes git treat dir as
			// a plain directory.
			cmd.Env = append(os.Environ(), "GIT_CEILING_DIRECTORIES="+filepath.Dir(dir))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git apply failed: %v\n%s\npatch:\n%s", err, out, patch)
			}
			got, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc[1] {
				t.Fatalf("after apply:\n%q\nwant:\n%q\npatch:\n%s", got, tc[1], patch)
			}
		})
	}
}
