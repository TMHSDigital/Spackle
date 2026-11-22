package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forbidden lists package-qualified identifiers that open a listening socket
// or define a server. Spackle must never bind a port in v0.1 (see
// docs/THREAT_MODEL.md, "Spackle does not become the backdoor").
var forbidden = map[string]map[string]bool{
	"net": {
		"Listen": true, "ListenTCP": true, "ListenUDP": true, "ListenIP": true,
		"ListenUnix": true, "ListenUnixgram": true, "ListenPacket": true,
		"ListenMulticastUDP": true, "ListenConfig": true, "FileListener": true,
	},
	"http": {
		"ListenAndServe": true, "ListenAndServeTLS": true, "Serve": true,
		"ServeTLS": true, "Server": true,
	},
	"tls": {"Listen": true, "NewListener": true},
}

// skipDirs are trees of intentionally vulnerable fixture code that is never
// compiled into the spackle binary.
var skipDirs = map[string]bool{
	".git": true, "bench": true, "examples": true, "dist": true, ".spackle": true, "node_modules": true,
}

func TestNoListenersInModule(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		checked++
		// Map local import names to the std packages we care about.
		local := map[string]string{}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			var std string
			switch p {
			case "net":
				std = "net"
			case "net/http":
				std = "http"
			case "crypto/tls":
				std = "tls"
			default:
				continue
			}
			name := std
			if imp.Name != nil {
				name = imp.Name.Name
			}
			local[name] = std
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if std, ok := local[id.Name]; ok && forbidden[std][sel.Sel.Name] {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s:%d uses %s.%s: Spackle must not open a network listener",
					filepath.ToSlash(rel), fset.Position(sel.Pos()).Line, std, sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no Go files were checked; the walk is misconfigured")
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}
