package report

import (
	"bytes"
	"html/template"
	"io"
)

// renderHTML writes one self-contained page: inline CSS, no script, no
// external request of any kind. Every value from the target reaches the page
// through html/template's contextual escaping and nothing is ever marked as
// trusted HTML, so target content cannot add markup.
func renderHTML(run Run, w io.Writer) error {
	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, buildDoc(run, cleanControl)); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

var htmlTemplate = template.Must(template.New("report").Parse(htmlSource))

const htmlSource = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Spackle report</title>
<style>
:root {
  --bg: #1B1714;
  --raised: #26201B;
  --border: #3A3029;
  --fg: #F3EDE4;
  --muted: #B5A999;
  --dim: #7F7466;
  --accent: #FF8A4C;
  --secondary: #C4A1FF;
  --critical: #FF5D5D;
  --high: #FF8A4C;
  --medium: #F2C14E;
  --low: #8FB8DE;
  --ok: #7BD389;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #F6F1EA;
    --raised: #FFFBF5;
    --border: #DDD2C4;
    --fg: #241C15;
    --muted: #5C5046;
    --dim: #7A6D5F;
    --accent: #B8480F;
    --secondary: #6B3FD4;
    --critical: #C62828;
    --high: #B8480F;
    --medium: #8A6100;
    --low: #2F6492;
    --ok: #237A3B;
  }
}
* { box-sizing: border-box; }
html { background: var(--bg); color: var(--fg); font-family: var(--sans); font-size: 16px; line-height: 1.55; }
body { margin: 0 auto; padding: 2.5rem 1.25rem 4rem; max-width: 60rem; }
h1 { font-size: 1.9rem; margin: 0 0 0.25rem; letter-spacing: -0.01em; }
h2 { font-size: 1.3rem; margin: 2.75rem 0 0.9rem; padding-bottom: 0.4rem; border-bottom: 1px solid var(--border); }
h3 { font-size: 1.15rem; margin: 0.5rem 0 0.25rem; overflow-wrap: anywhere; }
h4 { font-size: 0.8rem; margin: 1.6rem 0 0.5rem; color: var(--secondary); text-transform: uppercase; letter-spacing: 0.08em; }
p { margin: 0.4rem 0; overflow-wrap: anywhere; }
a { color: var(--accent); }
code, pre { font-family: var(--mono); font-size: 0.875rem; }
code { overflow-wrap: anywhere; }
pre { margin: 0.4rem 0 0.9rem; padding: 0.8rem 1rem; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; overflow-x: auto; white-space: pre; tab-size: 4; }
pre.diff { border-left: 3px solid var(--ok); }
ul, ol { margin: 0.3rem 0 0.8rem; padding-left: 1.4rem; }
li { margin: 0.15rem 0; overflow-wrap: anywhere; }
table { width: 100%; border-collapse: collapse; margin: 0.5rem 0 1rem; font-size: 0.925rem; }
th, td { text-align: left; vertical-align: top; padding: 0.5rem 0.65rem; border-bottom: 1px solid var(--border); overflow-wrap: anywhere; }
th { color: var(--muted); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
.meta { color: var(--muted); }
.wide { overflow-x: auto; }
.panel { background: var(--raised); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; }
.grid { display: grid; grid-template-columns: minmax(9rem, max-content) 1fr; gap: 0.3rem 1.25rem; margin: 0; }
.grid dt { color: var(--muted); }
.grid dd { margin: 0; overflow-wrap: anywhere; }
.k { color: var(--muted); font-weight: 600; margin-top: 0.7rem; }
.kv .k { margin-right: 0.4rem; }
.prose { white-space: pre-wrap; }
.notice { border-left: 3px solid var(--medium); padding: 0.75rem 1rem; background: var(--raised); border-radius: 0 6px 6px 0; }
.finding { margin: 1.5rem 0; border-left-width: 4px; }
.finding.sev-critical { border-left-color: var(--critical); }
.finding.sev-high { border-left-color: var(--high); }
.finding.sev-medium { border-left-color: var(--medium); }
.finding.sev-low { border-left-color: var(--low); }
.finding.sev-none { border-left-color: var(--dim); }
.badge { display: inline-block; padding: 0.05rem 0.5rem; border: 1px solid currentColor; border-radius: 999px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap; }
.badge.sev-critical { color: var(--critical); }
.badge.sev-high { color: var(--high); }
.badge.sev-medium { color: var(--medium); }
.badge.sev-low { color: var(--low); }
.badge.sev-none { color: var(--dim); }
.status-available { color: var(--ok); }
.status-missing { color: var(--medium); }
footer { margin-top: 3rem; color: var(--dim); font-size: 0.85rem; }
@media print { html { background: #fff; color: #000; } .panel { break-inside: avoid; } }
</style>
</head>
<body>
<header>
<h1>Spackle report</h1>
<p class="meta">Run <code>{{.RunID}}</code> &middot; outcome {{.Outcome}}</p>
</header>

<h2 id="run-summary">Run summary</h2>
<div class="panel">
<dl class="grid">
{{- range .Summary}}
<dt>{{.Label}}</dt><dd>{{if .Mono}}<code>{{.Value}}</code>{{else}}{{.Value}}{{end}}</dd>
{{- end}}
</dl>
</div>
<p><span class="k">Counts:</span> {{.Counts}}</p>

<h2 id="findings-summary">Findings summary</h2>
{{- if .NoFindings}}
<p class="notice">{{.NoFindings}}</p>
{{- else}}
<div class="wide">
<table>
<thead><tr><th>Id</th><th>Severity</th><th>Score</th><th>Confidence</th><th>Status</th><th>Title</th><th>Location</th></tr></thead>
<tbody>
{{- range .Active}}
<tr><td><a href="#{{.ID}}"><code>{{.ID}}</code></a></td><td><span class="badge sev-{{.Class}}">{{.Label}}</span></td><td>{{.Score}}</td><td>{{.Confidence}}</td><td>{{.Status}}</td><td>{{.Title}}</td><td><code>{{.Location}}</code></td></tr>
{{- end}}
</tbody>
</table>
</div>

<h2 id="findings">Findings</h2>
{{- range .Active}}
<section id="{{.ID}}" class="panel finding sev-{{.Class}}">
<p class="meta"><span class="badge sev-{{.Class}}">{{.Tag}}</span> <code>{{.ID}}</code> &middot; confidence {{.Confidence}} &middot; status {{.Status}}</p>
<h3>{{.Title}}</h3>
{{- range .Sections}}
<h4>{{.Title}}</h4>
{{- range .Blocks}}
{{- if eq .Kind "kv"}}
<p class="kv"><span class="k">{{.Label}}:</span> {{if .Mono}}<code>{{.Text}}</code>{{else}}{{.Text}}{{end}}</p>
{{- else if eq .Kind "para"}}
{{- if .Label}}
<p class="k">{{.Label}}</p>
{{- end}}
<p class="prose">{{.Text}}</p>
{{- else if eq .Kind "list"}}
<p class="k">{{.Label}}</p>
<ul>
{{- $mono := .Mono}}
{{- range .Items}}
<li>{{if $mono}}<code>{{.}}</code>{{else}}{{.}}{{end}}</li>
{{- end}}
</ul>
{{- else if eq .Kind "steps"}}
<p class="k">{{.Label}}</p>
<ol>
{{- range .Items}}
<li>{{.}}</li>
{{- end}}
</ol>
{{- else if eq .Kind "code"}}
{{- if .Label}}
<p class="k">{{.Label}}</p>
{{- end}}
<pre{{if eq .Lang "diff"}} class="diff"{{end}}><code>{{.Text}}</code></pre>
{{- end}}
{{- end}}
{{- end}}
</section>
{{- end}}
{{- end}}

<h2 id="dismissed">Dismissed by review</h2>
{{- if .Dismissed}}
<ul>
{{- range .Dismissed}}
<li><code>{{.ID}}</code> <span class="badge sev-{{.Class}}">{{.Tag}}</span> {{.Title}} at <code>{{.Location}}</code><br><span class="k">Reason:</span> {{.Reason}}</li>
{{- end}}
</ul>
{{- else}}
<p>No findings were dismissed.</p>
{{- end}}

<h2 id="skipped">What was skipped</h2>
{{- if .Skipped}}
<ul>
{{- range .Skipped}}
<li>{{.}}</li>
{{- end}}
</ul>
{{- else}}
<p>Nothing was skipped.</p>
{{- end}}

<h2 id="coverage">Coverage</h2>
<div class="panel">
<dl class="grid">
{{- range .Map}}
<dt>{{.Label}}</dt><dd>{{if .Mono}}<code>{{.Value}}</code>{{else}}{{.Value}}{{end}}</dd>
{{- end}}
</dl>
</div>
{{- if .Seeders}}
<div class="wide">
<table>
<thead><tr><th>Seeder</th><th>Status</th><th>Leads</th><th>Note</th></tr></thead>
<tbody>
{{- range .Seeders}}
<tr><td>{{.Name}}</td><td class="status-{{.Status}}">{{.Status}}</td><td>{{.Leads}}</td><td>{{.Note}}</td></tr>
{{- end}}
</tbody>
</table>
</div>
{{- else}}
<p>No seeder reported its status.</p>
{{- end}}

<h2 id="usage">Usage</h2>
<div class="panel">
<dl class="grid">
{{- range .Usage}}
<dt>{{.Label}}</dt><dd>{{.Value}}</dd>
{{- end}}
</dl>
</div>

<footer>{{if .PatchLine}}{{.PatchLine}}<br>{{end}}{{.SummaryLine}}</footer>
</body>
</html>
`
