package seed

import (
	"regexp"
	"strings"

	"go.yaml.in/yaml/v4"
)

var (
	wfPwnRequest = infraCheck{
		id: "workflow-pull-request-target-checkout", title: "pull_request_target workflow checks out the pull request's code",
		class: "ci-injection", cwe: "CWE-829", severity: "critical",
		detail: "pull_request_target runs with the base repository's secrets and a write token. Checking out the head of the pull request then runs code written by any contributor with those privileges.",
		fix:    "Use the pull_request trigger for anything that builds or tests contributed code. Keep pull_request_target for steps that never check out or execute the head.",
	}
	wfRunInjection = infraCheck{
		id: "workflow-script-injection", title: "Attacker-controlled context interpolated into a run script",
		class: "ci-injection", cwe: "CWE-94", severity: "high",
		detail: "The expression is expanded into the script text before the shell runs, so a crafted title, body, branch name or commit message becomes shell commands in the job.",
		fix:    "Pass the value through an env: entry and reference it as a quoted shell variable instead of interpolating it into the script.",
	}
	wfUnpinnedAction = infraCheck{
		id: "workflow-unpinned-action", title: "Action is not pinned to a commit SHA",
		class: "supply-chain", cwe: "CWE-829", severity: "low",
		detail: "A tag or branch reference can be moved, so the code this step runs can change without any change to the workflow, including after the action's repository is compromised.",
		fix:    "Pin the action to a full 40 character commit SHA and note the version in a comment.",
	}
	wfWriteAll = infraCheck{
		id: "workflow-permissions-write-all", title: "Workflow token has write access to everything",
		class: "ci-permissions", cwe: "CWE-732", severity: "medium",
		detail: "permissions: write-all gives every step, including third-party actions, a token that can push code, publish releases and change settings.",
		fix:    "Start from permissions: contents: read and grant each job only the scopes it uses.",
	}
	wfNoPermissions = infraCheck{
		id: "workflow-permissions-missing", title: "Workflow does not restrict its token permissions",
		class: "ci-permissions", cwe: "CWE-732", severity: "low",
		detail: "With no permissions block the token gets the repository default, which is read and write on older repositories and organizations.",
		fix:    "Add a top-level permissions block, starting from contents: read.",
	}

	wfUntrustedRe = regexp.MustCompile(`\$\{\{[^}]*(?:github\.event\.issue\.(?:title|body)|github\.event\.pull_request\.(?:title|body|head\.ref|head\.label)|github\.event\.comment\.body|github\.event\.review\.body|github\.event\.review_comment\.body|github\.event\.pages\.[^.}\s]+\.page_name|github\.event\.commits\.[^.}\s]+\.message|github\.event\.head_commit\.message|github\.head_ref)[^}]*\}\}`)
	wfSHARe       = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

func workflowLeads(rel, text string) []Lead {
	docs := yamlDocs(text)
	if len(docs) == 0 || docs[0].Kind != yaml.MappingNode {
		return nil
	}
	root := docs[0]
	jobsKey, jobs := yamlGet(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil // not a workflow
	}
	var leads []Lead
	lines := strings.Split(text, "\n")
	at := func(c infraCheck, line int) {
		leads = append(leads, c.lead(rel, line, lineAt(lines, line)))
	}

	hasPermissions := false
	checkPermissions := func(owner *yaml.Node) {
		k, v := yamlGet(owner, "permissions")
		if k == nil {
			return
		}
		hasPermissions = true
		if yamlScalar(v) == "write-all" {
			at(wfWriteAll, k.Line)
		}
	}
	checkPermissions(root)
	prTarget := hasTrigger(root, "pull_request_target")

	for i := 1; i < len(jobs.Content); i += 2 {
		job := yamlDeref(jobs.Content[i])
		checkPermissions(job)
		if k, v := yamlGet(job, "uses"); k != nil && actionUnpinned(yamlScalar(v)) {
			at(wfUnpinnedAction, k.Line)
		}
		for _, step := range yamlSeq(yamlPath(job, "steps")) {
			usesKey, usesVal := yamlGet(step, "uses")
			uses := yamlScalar(usesVal)
			if usesKey != nil && actionUnpinned(uses) {
				at(wfUnpinnedAction, usesKey.Line)
			}
			if prTarget && strings.HasPrefix(strings.ToLower(uses), "actions/checkout@") {
				if k, v := yamlGet(yamlPath(step, "with"), "ref"); k != nil && checksOutHead(yamlScalar(v)) {
					at(wfPwnRequest, k.Line)
				}
			}
			if k, v := yamlGet(step, "run"); k != nil && v != nil && v.Kind == yaml.ScalarNode && wfUntrustedRe.MatchString(v.Value) {
				for _, line := range untrustedLines(lines, k.Line, v.Value) {
					at(wfRunInjection, line)
				}
			}
		}
	}
	if !hasPermissions {
		at(wfNoPermissions, jobsKey.Line)
	}
	return leads
}

// hasTrigger reports whether the workflow's "on" lists event, in any of the
// three shapes GitHub accepts: a string, a list or a mapping.
func hasTrigger(root *yaml.Node, event string) bool {
	_, on := yamlGet(root, "on")
	if on == nil {
		return false
	}
	switch on.Kind {
	case yaml.ScalarNode:
		return on.Value == event
	case yaml.SequenceNode:
		for _, c := range on.Content {
			if c.Value == event {
				return true
			}
		}
	case yaml.MappingNode:
		k, _ := yamlGet(on, event)
		return k != nil
	}
	return false
}

func checksOutHead(ref string) bool {
	return strings.Contains(ref, "github.event.pull_request.head") || strings.Contains(ref, "github.head_ref")
}

// actionUnpinned reports whether a uses: reference can change under the
// workflow. Local actions live in this repository and docker references
// with a digest are immutable, so neither is reported.
func actionUnpinned(uses string) bool {
	uses = strings.TrimSpace(uses)
	switch {
	case uses == "", strings.HasPrefix(uses, "./"), strings.HasPrefix(uses, "../"):
		return false
	case strings.HasPrefix(uses, "docker://"):
		return !strings.Contains(uses, "@sha256:")
	}
	_, ref, ok := strings.Cut(uses, "@")
	return !ok || !wfSHARe.MatchString(ref)
}

// untrustedLines finds the source lines of a run script that interpolate an
// untrusted context. A block scalar's node only records where the script
// starts, so the script's own lines are searched from there; when nothing
// is found (a folded or quoted script) the key's line is reported.
func untrustedLines(lines []string, keyLine int, script string) []int {
	var out []int
	span := strings.Count(script, "\n") + 2
	for n := keyLine; n <= len(lines) && n <= keyLine+span; n++ {
		if wfUntrustedRe.MatchString(lines[n-1]) {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		out = append(out, keyLine)
	}
	return out
}
