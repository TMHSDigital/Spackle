package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/TMHSDigital/spackle/internal/agent/tools"
	"github.com/TMHSDigital/spackle/internal/budget"
	"github.com/TMHSDigital/spackle/internal/envelope"
	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/redact"
	"github.com/TMHSDigital/spackle/internal/sandbox"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// PoC is a proof of concept: files added to a copy of the target and the
// command that runs them inside the sandbox.
type PoC struct {
	Files       map[string]string `json:"files"`
	Command     []string          `json:"command"`
	Marker      string            `json:"marker"`
	Language    string            `json:"language"`
	Image       string            `json:"image"`
	Explanation string            `json:"explanation,omitempty"`
}

// ProofResult is the outcome of trying to demonstrate a finding.
type ProofResult struct {
	PoC          *PoC
	Demonstrated bool
	Output       string // redacted, clipped
	Isolation    string
	Reason       string // why it was not demonstrated
	Attempts     int
}

// Box runs things in the sandbox and accounts for them. The engine supplies
// it; it is the only way the prover and fixer can execute anything.
type Box struct {
	Runtime sandbox.Runtime
	Profile sandbox.Profile
	Budget  *budget.Budget
	Root    string
	// Record is called after every sandbox run so the engine can write the
	// ledger event and the evidence file.
	Record func(purpose string, spec sandbox.Spec, res sandbox.Result) error
}

// run executes one command against a copy of the target plus extra files.
func (b *Box) run(ctx context.Context, purpose, image string, cmd []string, files map[string]string) (sandbox.Result, error) {
	if err := b.Budget.UseSandbox(); err != nil {
		return sandbox.Result{}, err
	}
	spec := sandbox.Spec{Image: image, Cmd: cmd, SourceDir: b.Root, Files: files, Profile: b.Profile}
	res, err := b.Runtime.Run(ctx, spec)
	if err != nil {
		return res, err
	}
	if b.Record != nil {
		if rerr := b.Record(purpose, spec, res); rerr != nil {
			return res, rerr
		}
	}
	return res, nil
}

// pocPrefix is where a proof's files must live. A proof may add files; it
// may never replace a file of the target.
const pocPrefix = "spackle_poc"

// allowedPrograms lists what a proof's command may start with, by language.
// There is no shell here: a proof is one program run with an argument
// vector.
var allowedPrograms = map[string][]string{
	"python":     {"python", "python3"},
	"go":         {"go"},
	"javascript": {"node"},
	"typescript": {"node"},
}

// NewMarker returns the random token a proof must print to count as a
// demonstration. It is unguessable so that a proof cannot "succeed" by
// accident, for example by echoing a file that happens to contain it.
func NewMarker() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate proof marker: %w", err)
	}
	return "SPACKLE-PROOF-" + hex.EncodeToString(b[:]), nil
}

func proverSystem(s *envelope.Sealer) string {
	return roleFrame + "\n\n" + s.Preamble() + `

Your job in this step is to demonstrate one finding with a small proof of concept, so the owner
can see the flaw is real and can re-run the proof after fixing it. The proof runs inside an
isolated container against a copy of the owner's code: no network, no access to the host, a
read-only copy of the source, a time limit. Nothing it does can affect a real system.

Write the smallest proof that shows the flaw's effect and nothing more. Call the vulnerable
function or handler directly with a crafted input and assert the observable effect. Use a
harmless effect as evidence: a row the proof itself inserted being returned when it should not be,
a file the proof itself created being read through the traversal, a command that only prints a
fixed word. Do not write anything that would be useful outside this demonstration: no reverse
shells, no persistence, no data exfiltration, no scanning.

Constraints, enforced by the tool that runs your proof:
- Every file you add must be inside a new directory named spackle_poc/, or be named
  spackle_poc_test.go (for Go, placed in the package directory it tests). You cannot replace
  existing files.
- The command is a program and its arguments, not a shell line. Python targets: python. Go
  targets: go (for example ["go","test","-run","TestSpacklePoC","./pkg/..."]). JavaScript and
  TypeScript targets: node.
- Only the standard library and what is already in the repository are available. Nothing can be
  installed.
- The proof must print the exact marker you are given, and only after it has asserted that the
  flaw's effect happened. It must exit 0 when the flaw is demonstrated and non-zero otherwise.
  If the flaw is not there, the proof must fail without printing the marker.

Reply with one JSON object and nothing else.
If you can write a proof:
{"can_prove":true,"files":{"spackle_poc/poc.py":"file content"},"command":["python","spackle_poc/poc.py"],
 "explanation":"what the proof does and which observation shows the flaw"}
If a proof is not possible in this environment (it needs a network service, a database server,
packages that are not installed, or a running deployment):
{"can_prove":false,"reason":"what is missing"}`
}

type proverReply struct {
	CanProve    bool              `json:"can_prove"`
	Reason      string            `json:"reason"`
	Files       map[string]string `json:"files"`
	Command     []string          `json:"command"`
	Explanation string            `json:"explanation"`
}

// validatePoC checks a model-written proof before anything is run.
func validatePoC(root, language string, reply proverReply) (map[string]string, []string, error) {
	if len(reply.Files) == 0 {
		return nil, nil, errors.New("the proof has no files")
	}
	if len(reply.Files) > 4 {
		return nil, nil, fmt.Errorf("the proof has %d files; at most 4 are allowed", len(reply.Files))
	}
	files := map[string]string{}
	for name, content := range reply.Files {
		clean := path.Clean(strings.ReplaceAll(strings.TrimSpace(name), `\`, "/"))
		base := path.Base(clean)
		inDir := strings.HasPrefix(clean, pocPrefix+"/")
		if strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "..") || strings.Contains(clean, "/../") || strings.Contains(clean, ":") {
			return nil, nil, fmt.Errorf("proof file %q is not a relative path inside the project", name)
		}
		if !inDir && base != "spackle_poc_test.go" {
			return nil, nil, fmt.Errorf("proof file %q must be inside %s/ or be named spackle_poc_test.go", name, pocPrefix)
		}
		if len(content) > 64<<10 {
			return nil, nil, fmt.Errorf("proof file %q is larger than 64 KiB", name)
		}
		// A proof adds files. If the path already exists in the target the
		// proof would be replacing the owner's code.
		if _, err := walk.Resolve(root, clean); err == nil {
			return nil, nil, fmt.Errorf("proof file %q already exists in the target; a proof may only add files", name)
		}
		files[clean] = content
	}
	if len(reply.Command) == 0 || len(reply.Command) > 16 {
		return nil, nil, errors.New("the command must have between 1 and 16 arguments")
	}
	allowed := allowedPrograms[language]
	if !containsStr(allowed, reply.Command[0]) {
		return nil, nil, fmt.Errorf("the command must start with one of %v for a %s target, not %q", allowed, language, reply.Command[0])
	}
	for _, arg := range reply.Command {
		if strings.ContainsAny(arg, "\x00\n\r") || len(arg) > 400 {
			return nil, nil, errors.New("a command argument contains a control character or is too long")
		}
	}
	return files, reply.Command, nil
}

// Prove asks the model for a proof of concept and runs it in the sandbox. A
// proof that fails is sent back once with its output. The finding counts as
// demonstrated only when the run exits 0 and prints the marker.
func Prove(ctx context.Context, r *Runner, parent int64, sealer *envelope.Sealer, reg *tools.Registry, box *Box, language, image string, f finding.Finding) (ProofResult, error) {
	res := ProofResult{Isolation: box.Profile.WithDefaults().Summary()}
	marker, err := NewMarker()
	if err != nil {
		return res, err
	}
	brief := map[string]any{
		"title": f.Title, "class": f.Class, "location": f.Location.String(), "description": f.Flaw.Description,
		"flow": f.Flaw.Flow, "attack_steps": f.Exploitation.Steps, "language": language,
		"marker_to_print_on_success": marker,
	}
	raw, err := json.MarshalIndent(brief, "", " ")
	if err != nil {
		return res, err
	}
	system := proverSystem(sealer)
	user := "Write a proof of concept for this finding.\n\n" + sealer.Wrap("finding to demonstrate", string(raw))

	for attempt := 1; attempt <= 2; attempt++ {
		res.Attempts = attempt
		out, err := r.Run(ctx, parent, system, user, reg)
		if err != nil {
			return res, err
		}
		if out.Stopped == StopRefusal || out.Stopped == StopTruncated {
			res.Reason = "The model did not produce a proof (" + out.Stopped + ")."
			return res, nil
		}
		var reply proverReply
		if derr := decodeReply(out.Text, &reply); derr != nil {
			res.Reason = "The proof could not be parsed: " + derr.Error()
			return res, nil
		}
		if !reply.CanProve {
			res.Reason = "A proof could not be run in the sandbox: " + clip(strings.TrimSpace(reply.Reason), 400)
			return res, nil
		}
		files, cmd, verr := validatePoC(box.Root, language, reply)
		if verr != nil {
			res.Reason = "The proof was rejected before running: " + verr.Error()
			if attempt == 2 {
				return res, nil
			}
			user = "Your proof was rejected before running: " + verr.Error() + "\nFix that and reply again in the same JSON format.\n\n" +
				sealer.Wrap("finding to demonstrate", string(raw))
			continue
		}
		run, rerr := box.run(ctx, "poc", image, cmd, files)
		if rerr != nil {
			return res, rerr
		}
		output, _ := redact.Apply(strings.TrimSpace(run.Stdout + "\n" + run.Stderr))
		res.Output = clip(output, 4000)
		res.PoC = &PoC{Files: files, Command: cmd, Marker: marker, Language: language, Image: image, Explanation: clip(reply.Explanation, 800)}
		if !run.TimedOut && run.ExitCode == 0 && strings.Contains(run.Stdout+run.Stderr, marker) {
			res.Demonstrated = true
			res.Reason = ""
			return res, nil
		}
		switch {
		case run.TimedOut:
			res.Reason = "The proof timed out."
		case strings.Contains(run.Stdout+run.Stderr, marker):
			res.Reason = fmt.Sprintf("The proof printed the marker but exited with code %d.", run.ExitCode)
		default:
			res.Reason = fmt.Sprintf("The proof ran (exit code %d) and did not show the flaw.", run.ExitCode)
		}
		if attempt == 2 {
			return res, nil
		}
		user = "Your proof ran but did not demonstrate the flaw. " + res.Reason + " Its output was:\n" +
			sealer.Wrap("proof output", clip(output, 3000)) +
			"\n\nIf the proof was wrong, fix it and reply again in the same JSON format. If the output shows the flaw is not actually present, reply with can_prove false and say so.\n\n" +
			sealer.Wrap("finding to demonstrate", string(raw))
	}
	return res, nil
}

// SortedFiles returns the proof's file names in a stable order.
func (p *PoC) SortedFiles() []string {
	names := make([]string, 0, len(p.Files))
	for n := range p.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
