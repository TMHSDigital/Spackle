// Package lang is the one table of the languages Spackle can run code for:
// which programs a proof may start, the default sandbox image, the compile
// check after a patch and the command that runs one named test. Every other
// package reads the table, so adding a language is one entry here.
package lang

import "strings"

// Proof describes one language with full find, demonstrate and fix support.
// Other languages get findings and analysis only.
type Proof struct {
	// Name is the language name the walk and the mapper use ("go").
	Name string
	// Display is the name as written in prose ("Go").
	Display string
	// DefaultImage is the sandbox image used unless [sandbox.images] names
	// another.
	DefaultImage string
	// Programs lists what a proof's command may start with. There is no
	// shell: a proof is one program run with an argument vector.
	Programs []string

	compileCheck func(changed []string) []string
	singleTest   func(testCommand, name string) []string
}

// CompileCheck returns a cheap command that fails when a changed file no
// longer compiles or parses, or nil when the language has none for these
// files. It guards against a "fix" that only stops the proof by breaking
// the program.
func (p Proof) CompileCheck(changed []string) []string {
	if p.compileCheck == nil {
		return nil
	}
	return p.compileCheck(changed)
}

// SingleTest returns the command that runs the one test called name.
// testCommand is the target's own test command as the mapper detected it.
// The caller validates name: the vector is assembled here and a model never
// supplies it.
func (p Proof) SingleTest(testCommand, name string) []string {
	if p.singleTest == nil {
		return nil
	}
	return p.singleTest(testCommand, name)
}

func nodeCheck(changed []string) []string {
	if len(changed) == 1 {
		return []string{"node", "--check", changed[0]}
	}
	return nil
}

func nodeTest(_, name string) []string {
	return []string{"node", "--test", "--test-name-pattern", name}
}

// table lists the languages in the order they are named to the operator.
var table = []Proof{
	{
		Name: "go", Display: "Go", DefaultImage: "golang:1.27", Programs: []string{"go"},
		compileCheck: func([]string) []string { return []string{"go", "build", "./..."} },
		singleTest: func(_, name string) []string {
			return []string{"go", "test", "-count=1", "-run", "^" + name + "$", "./..."}
		},
	},
	{
		Name: "python", Display: "Python", DefaultImage: "python:3.13-slim", Programs: []string{"python", "python3"},
		compileCheck: func(changed []string) []string {
			return append([]string{"python", "-m", "py_compile"}, changed...)
		},
		singleTest: func(testCommand, name string) []string {
			if strings.Contains(testCommand, "pytest") {
				return []string{"python", "-m", "pytest", "-q", "-k", name}
			}
			return []string{"python", "-m", "unittest", "-k", name}
		},
	},
	{
		Name: "javascript", Display: "JavaScript", DefaultImage: "node:24-slim", Programs: []string{"node"},
		compileCheck: nodeCheck, singleTest: nodeTest,
	},
	{
		// node --check does not parse TypeScript, so there is no compile
		// check for it.
		Name: "typescript", Display: "TypeScript", DefaultImage: "node:24-slim", Programs: []string{"node"},
		singleTest: nodeTest,
	},
}

// Lookup returns the entry for a language name.
func Lookup(name string) (Proof, bool) {
	for _, p := range table {
		if p.Name == name {
			return p, true
		}
	}
	return Proof{}, false
}

// Supported reports whether proofs and fixes are run for the language.
func Supported(name string) bool {
	_, ok := Lookup(name)
	return ok
}

// Names returns the supported language names in table order.
func Names() []string {
	out := make([]string, 0, len(table))
	for _, p := range table {
		out = append(out, p.Name)
	}
	return out
}

// DefaultImages returns the default sandbox image of every language.
func DefaultImages() map[string]string {
	out := make(map[string]string, len(table))
	for _, p := range table {
		out[p.Name] = p.DefaultImage
	}
	return out
}

// DisplayList names the supported languages for a sentence: "Go, Python,
// JavaScript and TypeScript".
func DisplayList() string {
	names := make([]string, 0, len(table))
	for _, p := range table {
		names = append(names, p.Display)
	}
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}
