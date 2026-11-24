package seed

import (
	"context"
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

func (s infraSeeder) Run(ctx context.Context, _ string, files []walk.File) ([]Lead, error) {
	return runAlone(ctx, s, files)
}

func (infraSeeder) label() string { return "built-in infrastructure checks" }

func (infraSeeder) checks() func(walk.File) func(string) []Lead {
	return func(f walk.File) func(string) []Lead {
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
			return nil
		}
		return func(text string) []Lead { return check(f.Rel, text) }
	}
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
