package gitx

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseChangedLines(t *testing.T) {
	out := strings.Join([]string{
		"diff --git a/app.py b/app.py",
		"index 1111111..2222222 100644",
		"--- a/app.py",
		"+++ b/app.py",
		"@@ -3 +3 @@ def find(q):",
		"-    old",
		"+    new",
		"@@ -10,0 +11,2 @@",
		"+added one",
		// An added line that looks like a file header or a hunk header
		// is content, because the header's counts say so.
		"++++ b/not-a-file.py",
		"@@ -20,3 +21,0 @@",
		"-gone",
		"-gone",
		"-gone",
		"diff --git a/crlf.py b/crlf.py",
		"--- a/crlf.py\r",
		"+++ b/crlf.py\r",
		"@@ -1,2 +1,2 @@\r",
		"-a\r",
		"-b\r",
		"+A\r",
		"+B\r",
		"diff --git a/old name.py b/new name.py",
		"similarity index 90%",
		"rename from old name.py",
		"rename to new name.py",
		"--- a/old name.py",
		"+++ b/new name.py",
		"@@ -5 +5 @@",
		"-x",
		"+y",
		`\ No newline at end of file`,
		"diff --git a/new.py b/new.py",
		"new file mode 100644",
		"--- /dev/null",
		"+++ b/new.py",
		"@@ -0,0 +1,3 @@",
		"+1",
		"+2",
		"+3",
		`diff --git "a/tab\there.py" "b/tab\there.py"`,
		`--- "a/tab\there.py"`,
		`+++ "b/tab\there.py"`,
		"@@ -0,0 +1 @@",
		"+x",
		"diff --git a/top.py b/top.py",
		"--- a/top.py",
		"+++ b/top.py",
		"@@ -1,2 +0,0 @@",
		"-a",
		"-b",
		"diff --git a/image.png b/image.png",
		"Binary files a/image.png and b/image.png differ",
	}, "\n")
	want := map[string][]LineRange{
		"app.py":       {{3, 3}, {11, 12}, {21, 22}},
		"crlf.py":      {{1, 2}},
		"new name.py":  {{5, 5}},
		"new.py":       {{1, 3}},
		"tab\there.py": {{1, 1}},
		"top.py":       {{1, 1}},
	}
	if got := parseChangedLines(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("parseChangedLines =\n%v\nwant\n%v", got, want)
	}
}

func TestLineRangeOverlaps(t *testing.T) {
	r := LineRange{Start: 10, End: 12}
	for _, c := range []struct {
		start, end int
		want       bool
	}{
		{9, 9, false}, {10, 10, true}, {12, 0, true}, {13, 13, false}, {5, 10, true}, {12, 20, true}, {1, 100, true},
	} {
		if got := r.Overlaps(c.start, c.end); got != c.want {
			t.Errorf("Overlaps(%d, %d) = %v, want %v", c.start, c.end, got, c.want)
		}
	}
	if !WholeFile.Overlaps(123456, 123456) {
		t.Error("WholeFile does not cover a line")
	}
}

func TestChangedLinesSince(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "app.py", "a\nb\nc\nd\ne\n")
	writeFile(t, dir, "same.py", "x\n")
	commit(t, dir, "base")
	git(t, dir, "checkout", "-q", "-b", "feature")
	writeFile(t, dir, "app.py", "a\nB\nc\ne\n")
	writeFile(t, dir, "sub/new.py", "1\n2\n")
	commit(t, dir, "feature work")
	// Uncommitted work is not part of the change.
	writeFile(t, dir, "same.py", "wip\n")

	ctx := context.Background()
	got, err := ChangedLinesSince(ctx, dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]LineRange{
		"app.py":     {{2, 2}, {3, 4}},
		"sub/new.py": {{1, 2}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changed lines = %v, want %v", got, want)
	}
	if got, err = ChangedLinesSince(ctx, filepath.Join(dir, "sub"), "main"); err != nil || !reflect.DeepEqual(got, map[string][]LineRange{"new.py": {{1, 2}}}) {
		t.Fatalf("under sub: %v, err = %v", got, err)
	}
	for _, rev := range []string{"", "-x", "no-such-rev"} {
		if _, err := ChangedLinesSince(ctx, dir, rev); err == nil {
			t.Errorf("revision %q was accepted", rev)
		}
	}
}

func TestChangedLinesUncommitted(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "app.py", "a\nb\nc\n")
	ctx := context.Background()

	// Before the first commit every file is new.
	got, err := ChangedLinesUncommitted(ctx, dir)
	if err != nil || !reflect.DeepEqual(got, map[string][]LineRange{"app.py": {WholeFile}}) {
		t.Fatalf("before the first commit: %v, err = %v", got, err)
	}

	commit(t, dir, "base")
	writeFile(t, dir, "app.py", "a\nb\nc\nd\n")
	writeFile(t, dir, "scratch.py", "x\n")
	writeFile(t, dir, ".spackle/runs/x.txt", "state\n")
	got, err = ChangedLinesUncommitted(ctx, dir, ".spackle")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]LineRange{"app.py": {{4, 4}}, "scratch.py": {WholeFile}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changed lines = %v, want %v", got, want)
	}
}
