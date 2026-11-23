package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/sandbox"
)

type doctorRuntime struct{ present map[string]bool }

func (doctorRuntime) Name() string { return "podman" }
func (doctorRuntime) Run(context.Context, sandbox.Spec) (sandbox.Result, error) {
	return sandbox.Result{}, nil
}
func (d doctorRuntime) ImagePresent(_ context.Context, image string) bool { return d.present[image] }
func (doctorRuntime) Pull(context.Context, string) error                  { return nil }

// doctor reports what the sandbox package's detection reports, for every
// language that has a default image.
func TestDoctorUsesTheSandboxDetection(t *testing.T) {
	old := detectRuntime
	t.Cleanup(func() { detectRuntime = old })
	cfg := config.Default()

	asked := ""
	detectRuntime = func(_ context.Context, preferred string) (sandbox.Runtime, error) {
		asked = preferred
		return doctorRuntime{present: map[string]bool{cfg.Sandbox.Images["python"]: true}}, nil
	}
	rows := runtimeChecks(context.Background(), cfg)
	if asked != cfg.Sandbox.Runtime {
		t.Fatalf("detection was asked for %q, want the configured %q", asked, cfg.Sandbox.Runtime)
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.name] = r.status
	}
	want := map[string]string{"podman": "ok", "image go": "missing", "image python": "ok", "image javascript": "missing", "image typescript": "missing"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}

	detectRuntime = func(context.Context, string) (sandbox.Runtime, error) {
		return nil, fmt.Errorf("%w: docker is not on PATH; podman did not answer", sandbox.ErrNoRuntime)
	}
	rows = runtimeChecks(context.Background(), cfg)
	if len(rows) != 1 || rows[0].status != "missing" || !strings.Contains(rows[0].note, "podman did not answer") {
		t.Fatalf("rows = %+v", rows)
	}

	cfg.Sandbox.Runtime = "none"
	detectRuntime = func(context.Context, string) (sandbox.Runtime, error) {
		t.Fatal("detection ran although the sandbox is disabled")
		return nil, nil
	}
	if rows = runtimeChecks(context.Background(), cfg); len(rows) != 1 || rows[0].status != "warn" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestDoctorJSON(t *testing.T) {
	old := detectRuntime
	t.Cleanup(func() { detectRuntime = old })
	detectRuntime = func(context.Context, string) (sandbox.Runtime, error) {
		return doctorRuntime{present: map[string]bool{}}, nil
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"doctor", "--format", "json", "--config", emptyConfig(t)}, strings.NewReader(""), &stdout, &stderr)
	var got struct {
		Version string `json:"version"`
		Ready   bool   `json:"ready"`
		Checks  []struct{ Area, Name, Status, Note string }
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	if code != ExitOK || !got.Ready || got.Version == "" || len(got.Checks) == 0 {
		t.Fatalf("exit %d, report %+v, stderr %s", code, got, stderr.String())
	}
	found := false
	for _, c := range got.Checks {
		found = found || (c.Area == "Sandbox" && c.Name == "podman" && c.Status == "ok")
	}
	if !found {
		t.Errorf("the sandbox row is missing: %+v", got.Checks)
	}
	stdout.Reset()
	if code := Main([]string{"doctor", "--format", "yaml"}, strings.NewReader(""), &stdout, &stderr); code != ExitUsage {
		t.Errorf("an unknown format exited %d", code)
	}
}
