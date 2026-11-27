package report

import (
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/ledger"
)

// SARIF 2.1.0, shaped for GitHub code scanning. Only the properties Spackle
// fills are declared.

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	sarifInfoURI = "https://github.com/TMHSDigital/Spackle"
	sarifSrcRoot = "%SRCROOT%"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID string `json:"id"`
	// Name and the descriptions come from the class table, so an alert
	// reads "SQL injection" with its standard remediation instead of the
	// bare class id.
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  *sarifText     `json:"fullDescription,omitempty"`
	Help             *sarifText     `json:"help,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       sarifRuleProps `json:"properties"`
}

// sarifCodeFlow carries a finding's traced data flow, source to sink, so a
// viewer can step through it.
type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadFlowLocation `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location sarifFlowLocation `json:"location"`
}

type sarifFlowLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	Message          sarifText      `json:"message"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags"`
	// SecuritySeverity is the highest score among the rule's scored results.
	// GitHub reads the severity it displays from the rule.
	SecuritySeverity string `json:"security-severity,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	CodeFlows           []sarifCodeFlow   `json:"codeFlows,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          sarifResultProps  `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
}

type sarifLogical struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
}

type sarifResultProps struct {
	SecuritySeverity string `json:"security-severity,omitempty"`
	Confidence       string `json:"confidence"`
	ProofStatus      string `json:"proof_status"`
	// Verification and FixBranch are set when the finding has a patch.
	Verification string `json:"verification,omitempty"`
	FixBranch    string `json:"fix_branch,omitempty"`
}

func renderSARIF(run Run, w io.Writer) error {
	active := run.Active()
	rules, index := sarifRules(active)

	results := make([]sarifResult, 0, len(active))
	for _, f := range active {
		res := sarifResult{
			RuleID:              f.Class,
			RuleIndex:           index[f.Class],
			Level:               sarifLevel(f.Severity.Label),
			Message:             sarifText{Text: sarifMessage(f)},
			Locations:           []sarifLocation{sarifLocate(f.Location, run.RepoPrefix)},
			PartialFingerprints: sarifFingerprints(f),
			Properties: sarifResultProps{
				Confidence:  f.Confidence.Level,
				ProofStatus: f.Proof.Status,
			},
		}
		res.CodeFlows = sarifCodeFlows(f, run.RepoPrefix)
		if f.Remediation.Patch != "" {
			res.Properties.Verification = f.Remediation.Verification
			res.Properties.FixBranch = f.Remediation.Branch
		}
		if f.Status == finding.StatusFixed {
			// The proof no longer succeeds against the code, and the exit
			// code does not count this finding. Keep it visible, but not
			// as an error or warning, so the two signals agree.
			res.Level = "note"
		}
		if !f.Severity.Unscored {
			res.Properties.SecuritySeverity = fmt.Sprintf("%.1f", f.Severity.Score)
		}
		results = append(results, res)
	}

	return writeJSON(w, sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Spackle",
				InformationURI: sarifInfoURI,
				Version:        run.Version,
				Rules:          rules,
			}},
			Invocations: []sarifInvocation{{ExecutionSuccessful: run.Outcome != ledger.OutcomeFailed}},
			Results:     results,
		}},
	})
}

// sarifRules returns one rule per distinct finding class, sorted by id, and
// the index of each class in that list.
func sarifRules(active []finding.Finding) ([]sarifRule, map[string]int) {
	type agg struct {
		cwes     []int
		maxScore float64
		scored   bool
	}
	byClass := map[string]*agg{}
	var classes []string
	for _, f := range active {
		a, ok := byClass[f.Class]
		if !ok {
			a = &agg{}
			byClass[f.Class] = a
			classes = append(classes, f.Class)
		}
		for _, c := range f.CWE {
			if n, ok := cweNumber(c); ok {
				a.cwes = append(a.cwes, n)
			}
		}
		if !f.Severity.Unscored && (!a.scored || f.Severity.Score > a.maxScore) {
			a.maxScore, a.scored = f.Severity.Score, true
		}
	}
	sort.Strings(classes)

	rules := make([]sarifRule, 0, len(classes))
	index := make(map[string]int, len(classes))
	for i, class := range classes {
		a := byClass[class]
		sort.Ints(a.cwes)
		rule := sarifRule{
			ID:               class,
			ShortDescription: sarifText{Text: class},
			Properties:       sarifRuleProps{Tags: []string{"security"}},
		}
		if info := finding.Info(class); info.Name != "" {
			rule.Name = sarifRuleName(info.Name)
			rule.ShortDescription = sarifText{Text: info.Name}
			if len(info.Gains) > 0 {
				rule.FullDescription = &sarifText{Text: info.Name + ". What an attacker gains: " + strings.Join(info.Gains, "; ") + "."}
			}
			if info.Fix != "" {
				rule.Help = &sarifText{Text: info.Fix}
			}
		}
		prev := -1
		for _, n := range a.cwes {
			if n == prev {
				continue
			}
			prev = n
			if rule.HelpURI == "" {
				rule.HelpURI = fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", n)
			}
			rule.Properties.Tags = append(rule.Properties.Tags, fmt.Sprintf("external/cwe/cwe-%d", n))
		}
		if a.scored {
			rule.Properties.SecuritySeverity = fmt.Sprintf("%.1f", a.maxScore)
		}
		rules = append(rules, rule)
		index[class] = i
	}
	return rules, index
}

// cweNumber parses "CWE-89" into 89.
func cweNumber(s string) (int, bool) {
	rest, ok := strings.CutPrefix(s, "CWE-")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 0 || strings.TrimLeft(rest, "0123456789") != "" {
		return 0, false
	}
	return n, true
}

// sarifFingerprints is a result's partialFingerprints: the finding id,
// which includes the line, and the line-independent content fingerprint
// when the run has one. encoding/json writes map keys sorted, so the
// output does not depend on map order.
func sarifFingerprints(f finding.Finding) map[string]string {
	fp := map[string]string{"spackle/v1": f.ID}
	if f.Fingerprint != "" {
		fp["spackle/content/v1"] = f.Fingerprint
	}
	return fp
}

func sarifLevel(label string) string {
	switch label {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	}
	return "note"
}

func sarifMessage(f finding.Finding) string {
	parts := []string{strings.TrimSpace(f.Title)}
	if d := strings.TrimSpace(f.Flaw.Description); d != "" {
		parts = append(parts, d)
	}
	if r := strings.TrimSpace(f.Remediation.Summary); r != "" {
		parts = append(parts, "Remediation: "+r)
	}
	return normalizeNewlines(strings.Join(parts, "\n\n"))
}

// sarifLocate gives a file finding a physical location relative to the
// source root, and an endpoint finding a logical location. A finding with no
// file gets no physical location at all. Code scanning resolves a relative
// URI against the repository root, so when a subdirectory of a repository
// was scanned, its path from the root (prefix) is put in front.
func sarifLocate(l finding.Location, prefix string) sarifLocation {
	var loc sarifLocation
	if l.File != "" {
		file := l.File
		if prefix = strings.Trim(prefix, "/"); prefix != "" {
			file = prefix + "/" + file
		}
		phys := &sarifPhysical{ArtifactLocation: sarifArtifact{URI: sarifURI(file), URIBaseID: sarifSrcRoot}}
		if l.StartLine > 0 {
			phys.Region = &sarifRegion{StartLine: l.StartLine, EndLine: max(l.StartLine, l.EndLine)}
		}
		loc.PhysicalLocation = phys
	}
	if l.Endpoint != "" {
		name := l.Endpoint
		if l.Method != "" {
			name = strings.ToUpper(l.Method) + " " + name
		}
		if l.Parameter != "" {
			sep := "?"
			if strings.Contains(l.Endpoint, "?") {
				sep = "&"
			}
			name += sep + l.Parameter
		}
		loc.LogicalLocations = []sarifLogical{{FullyQualifiedName: name}}
	}
	return loc
}

// sarifURI turns a target-relative path into a relative URI reference with
// forward slashes and percent-encoding.
func sarifURI(file string) string {
	p := strings.TrimLeft(strings.ReplaceAll(file, `\`, "/"), "/")
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	if strings.Contains(segs[0], ":") {
		// A colon in the first segment would read as a URI scheme.
		return "./" + strings.Join(segs, "/")
	}
	return strings.Join(segs, "/")
}

// sarifRuleName turns a class name into the PascalCase identifier SARIF
// asks for in a rule's name.
func sarifRuleName(name string) string {
	var b strings.Builder
	upper := true
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z' && upper:
			b.WriteRune(r - 'a' + 'A')
			upper = false
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			upper = false
		default:
			upper = true
		}
	}
	return b.String()
}

// sarifCodeFlows renders a traced flow of two or more steps. A single step
// is the finding's own location and adds nothing. Steps without a file (a
// running-target step) are left out. The quote in each message is the one
// stored in the finding, which was taken from the redacted view of the file.
func sarifCodeFlows(f finding.Finding, prefix string) []sarifCodeFlow {
	if len(f.Flaw.Flow) < 2 {
		return nil
	}
	var locs []sarifThreadFlowLocation
	for _, step := range f.Flaw.Flow {
		if step.File == "" {
			continue
		}
		file := step.File
		if p := strings.Trim(prefix, "/"); p != "" {
			file = p + "/" + file
		}
		phys := &sarifPhysical{ArtifactLocation: sarifArtifact{URI: sarifURI(file), URIBaseID: sarifSrcRoot}}
		if step.Line > 0 {
			phys.Region = &sarifRegion{StartLine: step.Line, EndLine: step.Line}
		}
		msg := step.Role
		if note := strings.TrimSpace(step.Note); note != "" {
			msg += ": " + note
		} else if quote := strings.TrimSpace(step.Quote); quote != "" {
			msg += ": " + quote
		}
		locs = append(locs, sarifThreadFlowLocation{Location: sarifFlowLocation{PhysicalLocation: phys, Message: sarifText{Text: normalizeNewlines(msg)}}})
	}
	if len(locs) < 2 {
		return nil
	}
	return []sarifCodeFlow{{ThreadFlows: []sarifThreadFlow{{Locations: locs}}}}
}
