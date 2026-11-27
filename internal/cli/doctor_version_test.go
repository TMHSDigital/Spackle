package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/seed"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// versionedSeeder stands in for an installed external scanner that reports
// a version.
type versionedSeeder struct{ name, version string }

func (v versionedSeeder) Name() string                   { return v.name }
func (versionedSeeder) Available() (bool, string)        { return true, "" }
func (v versionedSeeder) Version(context.Context) string { return v.version }
func (versionedSeeder) Run(context.Context, string, []walk.File) ([]seed.Lead, error) {
	return nil, nil
}

// doctor shows an installed scanner's version, and warns when it is not
// the version the adapter is tested with or cannot be read.
func TestScannerVersionCheck(t *testing.T) {
	tested := seed.TestedVersions["gitleaks"]
	for _, c := range []struct {
		version, status, note string
	}{
		{tested, "ok", "version " + tested},
		{"0.0.1", "warn", "version 0.0.1; Spackle is tested with " + tested},
		{"", "warn", "its version could not be read; Spackle is tested with " + tested},
	} {
		status, note := scannerVersionCheck(context.Background(), versionedSeeder{"gitleaks", c.version})
		if status != c.status || !strings.Contains(note, c.note) {
			t.Errorf("version %q: [%s] %s, want [%s] containing %q", c.version, status, note, c.status, c.note)
		}
	}
}
