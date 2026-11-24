package config

import (
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/sandbox"
)

// Every limit of the [sandbox] table reaches the profile, so a scan, debug
// and verify run their containers under the same limits.
func TestSandboxProfileCarriesEveryLimit(t *testing.T) {
	s := Sandbox{Network: "scope", MemoryMB: 512, CPUs: 1.5, PIDs: 64, Timeout: Duration{90 * time.Second}}
	want := sandbox.Profile{Network: "scope", MemoryMB: 512, CPUs: 1.5, PIDs: 64, Timeout: 90 * time.Second}
	if got := s.Profile(); got != want {
		t.Fatalf("Profile() = %+v, want %+v", got, want)
	}
	if got := Default().Sandbox.Profile(); got.Validate() != nil {
		t.Fatalf("the default profile does not validate: %v", got.Validate())
	}
}
