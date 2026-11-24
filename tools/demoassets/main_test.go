package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/finding"
)

func TestFindingSectionCutsOneFindingAndDemotesItsHeadings(t *testing.T) {
	md := "## Findings\r\n\r\n### SPK-00000001: First\n\ntext\n\n" +
		"### SPK-00000002: Second\n\n#### Identity\n\n- **Id:** `SPK-00000002`\n\n```text\n# not a heading\n```\n\n" +
		"### SPK-00000003: Third\n\nmore\n\n## Dismissed by review\n"
	got, err := findingSection(md, "SPK-00000002")
	if err != nil {
		t.Fatal(err)
	}
	want := "#### SPK-00000002: Second\n\n##### Identity\n\n- **Id:** `SPK-00000002`\n\n```text\n# not a heading\n```\n"
	if got != want {
		t.Fatalf("section =\n%q\nwant\n%q", got, want)
	}
	// The last finding ends at the next second-level heading.
	if got, err = findingSection(md, "SPK-00000003"); err != nil || got != "#### SPK-00000003: Third\n\nmore\n" {
		t.Fatalf("last section = %q, err = %v", got, err)
	}
	if _, err := findingSection(md, "SPK-FFFFFFFF"); err == nil {
		t.Fatal("a finding that is not in the report gave a section")
	}
}

func TestSiteFindingUsesOnlyFieldsOfTheFinding(t *testing.T) {
	f := finding.Finding{
		ID: "SPK-0A1B2C3D", Title: "Path traversal in <name>", CWE: []string{"CWE-22"},
		Location: finding.Location{Method: "GET", Endpoint: "/file", Parameter: "name"},
		Severity: finding.Severity{Label: "high", Score: 8.7, Vector: "CVSS:4.0/AV:N"},
		Flaw:     finding.Flaw{Description: "GET /file returned a system file. The parameter is used as a path."},
		Proof:    finding.Proof{Result: "a & b", Artifacts: []string{"evidence/exchanges/X-0001.json"}},
	}
	f.Confidence.Level = finding.ConfidenceDemonstrated
	f.Exploitation.ChainsInto = []string{"Credential theft from configuration files"}
	f.Remediation.Summary = "Resolve the name against a base directory."
	f.Remediation.Verification = "unverified"
	got := siteFinding(f)
	for _, want := range []string{
		`SPK-0A1B2C3D <span class="sev">[HIGH 8.7]</span> Path traversal in &lt;name&gt;`,
		`CWE-22`, `CVSS:4.0/AV:N`,
		`<span class="conf">demonstrated</span> <span class="k">·</span> evidence/exchanges/X-0001.json`,
		`<p>GET /file returned a system file:</p>`,
		`<code class="out">a &amp; b</code>`,
		`<p class="say">The parameter is used as a path.</p>`,
		`<p>Chains into: credential theft from configuration files.</p>`,
		`<p class="say">Resolve the name against a base directory.</p>`,
		`Verification: unverified`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the site finding lacks %q:\n%s", want, got)
		}
	}
}

func TestMentionsReportsOrRewritesAStaleId(t *testing.T) {
	file := filepath.Join(t.TempDir(), "doc.md")
	re := regexp.MustCompile(`findings/SPK-[0-9A-F]{8}/finding\.json`)
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("It is `findings/SPK-11111111/finding.json` from that run.\n")
	const want = "findings/SPK-22222222/finding.json"
	if stale, err := mentions(file, re, want, true); err != nil || len(stale) != 1 {
		t.Fatalf("check: stale = %v, err = %v", stale, err)
	}
	if stale, err := mentions(file, re, want, false); err != nil || len(stale) != 0 {
		t.Fatalf("write: stale = %v, err = %v", stale, err)
	}
	if raw, _ := os.ReadFile(file); !strings.Contains(string(raw), want) {
		t.Fatalf("the id was not rewritten: %s", raw)
	}
	if stale, err := mentions(file, re, want, true); err != nil || len(stale) != 0 {
		t.Fatalf("after the rewrite: stale = %v, err = %v", stale, err)
	}
	write("The sentence was removed.\n")
	if _, err := mentions(file, re, want, true); err == nil {
		t.Fatal("a document that no longer names the file was accepted")
	}
}
