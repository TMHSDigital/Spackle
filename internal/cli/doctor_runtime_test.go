package cli

import (
	"context"
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
