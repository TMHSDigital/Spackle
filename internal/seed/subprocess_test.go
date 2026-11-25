package seed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/walk"
)

// TestMain lets the test binary stand in for an external scanner: started
// with SPACKLE_STUB_SCANNER set, it prints what the STUB_* variables say
// and exits with STUB_EXIT, instead of running the tests.
func TestMain(m *testing.M) {
	if os.Getenv("SPACKLE_STUB_SCANNER") != "" {
		_, _ = io.WriteString(os.Stdout, os.Getenv("STUB_STDOUT"))
		_, _ = io.WriteString(os.Stderr, os.Getenv("STUB_STDERR"))
		code, _ := strconv.Atoi(os.Getenv("STUB_EXIT"))
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// stubScanner puts a copy of the test binary on PATH under a scanner's
// name and returns an adapter that runs it. Its report is a JSON list of
// file names, one lead per name.
func stubScanner(t *testing.T, stdout, stderr string, exit int) *external {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	name := "spackle-stub-scanner"
	exe := name
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, exe), b, 0o755); err != nil { //nolint:gosec // a test binary must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SPACKLE_STUB_SCANNER", "1")
	t.Setenv("STUB_STDOUT", stdout)
	t.Setenv("STUB_STDERR", stderr)
	t.Setenv("STUB_EXIT", strconv.Itoa(exit))
	return &external{
		name: "stub", bin: name, site: "example.test", quietExit: []int{3},
		args: func(string, []walk.File) ([]string, bool) { return nil, true },
		leads: func(data []byte, _ string, _ *parseStats) ([]Lead, error) {
			var files []string
			if err := json.Unmarshal(data, &files); err != nil {
				return nil, fmt.Errorf("stub report: %w", err)
			}
			var leads []Lead
			for _, f := range files {
				leads = append(leads, Lead{RuleID: "stub", File: f, Line: 1})
			}
			return leads, nil
		},
	}
}

func TestExternalScannerSubprocess(t *testing.T) {
	root := t.TempDir()
	for _, c := range []struct {
		name           string
		stdout, stderr string
		exit           int
		leads          int
		wantErr        []string
	}{
		{name: "exit 0, no output", exit: 0},
		{name: "quiet exit code, no output", exit: 3},
		{name: "failure without a report", stderr: "boom", exit: 2, wantErr: []string{"failed without producing a report", "boom"}},
		{name: "findings exit with a report", stdout: `["a.py","b.py"]`, exit: 1, leads: 2},
		{name: "failure with output that is not a report", stdout: "not json", exit: 1, wantErr: []string{"not a readable report"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := stubScanner(t, c.stdout, c.stderr, c.exit)
			leads, err := e.Run(context.Background(), root, nil)
			if len(c.wantErr) == 0 && err != nil {
				t.Fatalf("err = %v", err)
			}
			for _, want := range c.wantErr {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, want it to mention %q", err, want)
				}
			}
			if len(leads) != c.leads {
				t.Fatalf("leads = %d, want %d", len(leads), c.leads)
			}
		})
	}

	t.Run("report larger than the limit", func(t *testing.T) {
		old := maxScannerOutput
		maxScannerOutput = 16
		t.Cleanup(func() { maxScannerOutput = old })
		e := stubScanner(t, `["a.py","b.py","c.py","d.py"]`, "", 1)
		leads, err := e.Run(context.Background(), root, nil)
		if err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("err = %v, want it to mention %q", err, "larger than")
		}
		if leads != nil {
			t.Fatalf("leads = %v, want none", leads)
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		e := stubScanner(t, `["a.py"]`, "", 0)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := e.Run(ctx, root, nil)
		if err == nil || !strings.Contains(err.Error(), "did not finish") || !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
}
