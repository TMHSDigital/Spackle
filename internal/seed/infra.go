package seed

import (
	"context"
	"fmt"
	"strings"

	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// infraSeeder checks deployment files: Dockerfiles, Kubernetes manifests,
// Terraform and GitHub workflows. Each kind lives in its own file.
type infraSeeder struct{}

func (infraSeeder) Name() string { return "builtin-infra" }

func (infraSeeder) Available() (bool, string) { return true, "" }

func isWorkflowPath(rel string) bool {
	low := strings.ToLower(rel)
	if !strings.HasSuffix(low, ".yml") && !strings.HasSuffix(low, ".yaml") {
		return false
	}
	return strings.HasPrefix(low, ".github/workflows/") || strings.Contains(low, "/.github/workflows/")
}

func isTerraformPath(rel string) bool {
	low := strings.ToLower(rel)
	return strings.HasSuffix(low, ".tf") || strings.HasSuffix(low, ".tfvars")
}

func (infraSeeder) Run(ctx context.Context, _ string, files []walk.File) ([]Lead, error) {
	var leads []Lead
	var firstErr error
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return leads, fmt.Errorf("built-in infrastructure checks stopped early: %w; rerun the scan to cover the remaining files", err)
		}
		var check func(rel, text string) []Lead
		switch {
		case f.Lang == "dockerfile":
			check = dockerLeads
		case isTerraformPath(f.Rel):
			check = terraformLeads
		case isWorkflowPath(f.Rel):
			check = workflowLeads
		case f.Lang == "yaml":
			check = k8sLeads
		default:
			continue
		}
		text, err := walk.ReadText(f.Abs)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("built-in infrastructure checks could not read %s: %w; check the file's permissions and rerun", f.Rel, err)
			}
			continue
		}
		leads = append(leads, check(f.Rel, text)...)
	}
	return leads, firstErr
}

// infraCheck is the fixed part of an infrastructure lead.
type infraCheck struct {
	id, title, class, cwe, severity, detail, fix string
}

// lead builds a lead for check at line. snip is the text to show; it is
// redacted and truncated here so no check can forget to.
func (c infraCheck) lead(rel string, line int, snip string) Lead {
	return Lead{
		RuleID:   c.id,
		Title:    c.title,
		Class:    c.class,
		Surface:  finding.SurfaceInfra,
		CWE:      []string{c.cwe},
		Severity: c.severity,
		File:     rel,
		Line:     line,
		Snippet:  snippet(snip),
		Detail:   c.detail,
		Fix:      c.fix,
	}
}
