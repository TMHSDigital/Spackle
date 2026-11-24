package seed

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every infraCheck defined in the package is in infraChecks, so the rule
// listing cannot miss one.
func TestInfraChecksListsEveryCheck(t *testing.T) {
	defined := map[string]bool{}
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok || len(vs.Values) != 1 {
				return true
			}
			if cl, ok := vs.Values[0].(*ast.CompositeLit); ok {
				if id, ok := cl.Type.(*ast.Ident); ok && id.Name == "infraCheck" {
					defined[vs.Names[0].Name] = true
				}
			}
			return true
		})
	}
	ids := map[string]bool{}
	for _, c := range infraChecks {
		if ids[c.id] {
			t.Errorf("%s is listed twice", c.id)
		}
		ids[c.id] = true
		if infraLang(c.id) == "" {
			t.Errorf("%s has no known file kind", c.id)
		}
	}
	if len(defined) == 0 || len(infraChecks) != len(defined) {
		t.Fatalf("infraChecks has %d checks, the package defines %d: add the new ones to infraChecks", len(infraChecks), len(defined))
	}
}

func TestBuiltinRulesListsEverySeedersRules(t *testing.T) {
	rules := BuiltinRules()
	bySource := map[string]int{}
	seen := map[string]bool{}
	for _, r := range rules {
		bySource[r.Source]++
		key := r.Source + ":" + r.ID
		if seen[key] {
			t.Errorf("%s is listed twice", key)
		}
		seen[key] = true
		if r.ID == "" || r.Class == "" || r.Severity == "" || r.CWE == "" {
			t.Errorf("incomplete rule %+v", r)
		}
	}
	if bySource["builtin-code"] != len(codeRules) || bySource["builtin-infra"] != len(infraChecks) || bySource["builtin-secrets"] == 0 {
		t.Fatalf("rules by source = %v", bySource)
	}
}

func TestUnknownBuiltinRulesCatchesTypos(t *testing.T) {
	got := UnknownBuiltinRules([]string{
		"py-sql-fstring", "py-sql-fstrng", "docker-no-usr", "builtin-code:go-nope",
		"builtin-infra:docker-no-user", "semgrep:python.lang.security.audit", "B101", "  docker-no-user ",
	})
	if strings.Join(got, ",") != "py-sql-fstrng,docker-no-usr,builtin-code:go-nope" {
		t.Fatalf("unknown = %v", got)
	}
}
