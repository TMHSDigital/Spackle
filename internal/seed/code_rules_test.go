package seed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/finding"
	"github.com/TMHSDigital/spackle/internal/walk"
)

// writeTree writes files (forward-slash relative path -> content) under a
// new temporary directory and returns the directory and its safe listing.
func writeTree(t *testing.T, files map[string]string) (string, []walk.File) {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := walk.List(root)
	if err != nil {
		t.Fatal(err)
	}
	return root, res.Files
}

func ruleIDs(leads []Lead) []string {
	var out []string
	for _, l := range leads {
		out = append(out, l.RuleID)
	}
	return out
}

func hasRule(leads []Lead, id string) bool {
	for _, l := range leads {
		if l.RuleID == id {
			return true
		}
	}
	return false
}

type ruleCase struct {
	match []string // each must produce a lead for the rule
	safe  []string // each must not
}

// "\x60" is a backtick, which cannot appear in a raw string literal.
var ruleCases = map[string]ruleCase{
	"go-sql-sprintf": {
		match: []string{`q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)`},
		safe:  []string{`msg := fmt.Sprintf("selected %s rows", n)`, `q := fmt.Sprintf("SELECT * FROM users LIMIT %d", limit)`},
	},
	"go-sql-concat": {
		match: []string{`rows, err := db.Query("SELECT * FROM users WHERE id = " + id)`, `db.ExecContext(ctx, "DELETE FROM t WHERE id = " + id)`},
		safe:  []string{`rows, err := db.Query("SELECT * FROM users WHERE id = $1", id)`, `log.Print("SELECT count: " + n)`},
	},
	"py-sql-fstring": {
		match: []string{`cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`},
		safe:  []string{`cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`},
	},
	"py-sql-fstring-var": {
		match: []string{`sql = f"SELECT id, title FROM notes WHERE title LIKE '%{q}%'"`, `    query = f'DELETE FROM t WHERE id = {uid}'`},
		safe:  []string{`sql = "SELECT id FROM notes WHERE title LIKE ?"`, `msg = f"Select one of {choices}"`, `label = f"{count} rows selected"`},
	},
	"js-sql-template-var": {
		match: []string{"const sql = \x60SELECT * FROM users WHERE id = ${id}\x60"},
		safe:  []string{"const sql = \x60SELECT * FROM users WHERE id = ?\x60", "const msg = \x60Update for ${name}\x60 // not sql"},
	},
	"go-sql-concat-var": {
		match: []string{`q := "SELECT * FROM users WHERE name = '" + name + "'"`},
		safe:  []string{`q := "SELECT * FROM users WHERE name = $1"`, `title := "Select " + name`},
	},
	"py-sql-percent-format": {
		match: []string{`cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)`},
		safe:  []string{`cursor.execute("SELECT * FROM users WHERE name = %s", (name,))`},
	},
	"py-sql-str-format": {
		match: []string{`cur.execute("SELECT * FROM t WHERE id = {}".format(uid))`},
		safe:  []string{`cur.execute("SELECT * FROM t WHERE id = ?", (uid,))`},
	},
	"py-sql-concat": {
		match: []string{`cur.execute("SELECT * FROM t WHERE id = " + uid)`},
		safe:  []string{`cur.execute("SELECT * FROM t WHERE id = ?", [uid])`},
	},
	"js-sql-template": {
		match: []string{"db.query(\x60SELECT * FROM users WHERE id = ${req.params.id}\x60)"},
		safe:  []string{`db.query("SELECT * FROM users WHERE id = $1", [id])`, "db.query(\x60SELECT * FROM users\x60)", "db.query(sql\x60SELECT * FROM users WHERE id = ${id}\x60)"},
	},
	"js-sql-concat": {
		match: []string{`connection.query("SELECT * FROM users WHERE name = '" + name + "'")`},
		safe:  []string{`connection.query("SELECT * FROM users WHERE name = ?", [name])`},
	},
	"go-exec-shell": {
		match: []string{`cmd := exec.Command("sh", "-c", userInput)`, `exec.CommandContext(ctx, "bash", "-c", "ping " + host)`},
		safe:  []string{`cmd := exec.Command("ls", "-l")`, `cmd := exec.Command("sh", "-c", "echo hello")`},
	},
	"py-os-system": {
		match: []string{`os.system("ping " + host)`, `os.system(cmd)`, `os.system(f"ping {host}")`},
		safe:  []string{`os.system("clear")`},
	},
	"py-subprocess-shell": {
		match: []string{`subprocess.run(cmd, shell=True)`, `subprocess.check_output("ping " + host, shell=True)`},
		safe:  []string{`subprocess.run(["ls", "-l"], shell=False)`, `subprocess.run(["ls", "-l"])`, `subprocess.run("ls -l", shell=True)`},
	},
	"js-child-process-exec": {
		match: []string{"child_process.exec(\x60ping ${host}\x60)", `exec("ping " + host, cb)`, `cp.exec(cmd + " -v")`},
		safe:  []string{`child_process.exec("ls -l")`, `child_process.execFile("ping", [host])`, "const m = re.exec(\x60${a}\x60)"},
	},
	"py-eval-exec": {
		match: []string{`result = eval(expr)`, `exec(request.form["code"])`},
		safe:  []string{`result = eval("1 + 1")`, `model.eval()`, `ast.literal_eval(expr)`},
	},
	"js-eval": {
		match: []string{`const v = eval(input)`, `const f = new Function("a", body)`},
		safe:  []string{`const v = eval("1 + 1")`, `const f = new Function("a", "return a")`, `obj.eval(x)`},
	},
	"py-pickle-load": {
		match: []string{`obj = pickle.loads(data)`},
		safe:  []string{`blob = pickle.dumps(obj)`, `obj = json.loads(data)`},
	},
	"py-marshal-load": {
		match: []string{`code = marshal.loads(blob)`},
		safe:  []string{`blob = marshal.dumps(code)`},
	},
	"py-yaml-load": {
		match: []string{`cfg = yaml.load(f)`, `cfg = yaml.load(f, Loader=yaml.Loader)`},
		safe:  []string{`cfg = yaml.safe_load(f)`, `cfg = yaml.load(f, Loader=yaml.SafeLoader)`},
	},
	"js-unserialize": {
		match: []string{`const obj = serialize.unserialize(req.cookies.profile)`},
		safe:  []string{`const obj = JSON.parse(req.cookies.profile)`},
	},
	"py-path-from-request": {
		match: []string{`path = os.path.join(UPLOADS, request.args.get("name"))`, `f = open(request.args["file"])`},
		safe:  []string{`path = os.path.join(UPLOADS, secure_filename(request.files["f"].filename))`, `path = os.path.join(UPLOADS, "report.pdf")`},
	},
	"go-file-from-request": {
		match: []string{`http.ServeFile(w, r, "/data/" + r.URL.Query().Get("file"))`, `f, err := os.Open(r.FormValue("path"))`},
		safe:  []string{`http.ServeFile(w, r, "static/index.html")`, `http.ServeFile(w, r, filepath.Join(base, filepath.Base(r.URL.Query().Get("file"))))`},
	},
	"js-file-from-request": {
		match: []string{`res.sendFile(req.query.file)`, `fs.readFile(req.params.name, cb)`},
		safe:  []string{`res.sendFile("index.html", { root: publicDir })`, `fs.readFile("config.json", cb)`},
	},
	"py-http-request-url": {
		match: []string{`r = requests.get(request.args.get("url"))`, `data = urllib.request.urlopen(request.args["u"]).read()`},
		safe:  []string{`r = requests.get("https://api.example.com/v1/status")`, `r = requests.get(API_URL, params=params)`},
	},
	"go-http-request-url": {
		match: []string{`resp, err := http.Get(r.URL.Query().Get("url"))`, `resp, err := http.Get(r.FormValue("target"))`},
		safe:  []string{`resp, err := http.Get("https://api.example.com/health")`, `resp, err := http.Get(cfg.UpstreamURL)`},
	},
	"js-http-request-url": {
		match: []string{`const r = await fetch(req.query.url)`, `const r = await axios.get(req.body.target)`},
		safe:  []string{`const r = await fetch("https://api.example.com/health")`, `const r = await axios.get(config.upstream)`},
	},
	"go-weak-hash": {
		match: []string{`h := md5.New()`, `sum := sha1.Sum(data)`},
		safe:  []string{`h := sha256.New()`, `sum := sha256.Sum256(data)`},
	},
	"py-weak-hash": {
		match: []string{`digest = hashlib.md5(data).hexdigest()`, `digest = hashlib.sha1(data).hexdigest()`},
		safe:  []string{`digest = hashlib.sha256(data).hexdigest()`, `etag = hashlib.md5(data, usedforsecurity=False).hexdigest()`},
	},
	"js-weak-hash": {
		match: []string{`const h = crypto.createHash('md5').update(s).digest('hex')`, `const h = crypto.createHash("sha1")`},
		safe:  []string{`const h = crypto.createHash('sha256').update(s).digest('hex')`},
	},
	"go-weak-cipher": {
		match: []string{`block, err := des.NewCipher(key)`, `c, err := rc4.NewCipher(key)`},
		safe:  []string{`block, err := aes.NewCipher(key)`},
	},
	"py-weak-cipher": {
		match: []string{`cipher = DES.new(key, DES.MODE_CBC, iv)`, `cipher = AES.new(key, AES.MODE_ECB)`},
		safe:  []string{`cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)`},
	},
	"js-weak-cipher": {
		match: []string{`const c = crypto.createCipheriv('des-ede3-cbc', key, iv)`, `const c = crypto.createCipheriv("aes-128-ecb", key, null)`},
		safe:  []string{`const c = crypto.createCipheriv('aes-256-gcm', key, iv)`},
	},
	"go-tls-skip-verify": {
		match: []string{`tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}`},
		safe:  []string{`tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}}`, `cfg := &tls.Config{MinVersion: tls.VersionTLS12}`},
	},
	"py-tls-verify-false": {
		match: []string{`r = requests.get(url, verify=False)`},
		safe:  []string{`r = requests.get(url, verify=True)`, `claims = jwt.decode(tok, verify=False)`},
	},
	"js-tls-reject-unauthorized": {
		match: []string{`const agent = new https.Agent({ rejectUnauthorized: false })`, `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"`, `process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0`},
		safe:  []string{`const agent = new https.Agent({ rejectUnauthorized: true })`},
	},
	"go-math-rand-secret": {
		match: []string{`token := fmt.Sprintf("%06d", rand.Intn(1000000))`},
		safe:  []string{`delay := time.Duration(rand.Intn(100)) * time.Millisecond`, `n, err := rand.Read(tokenBytes)`},
	},
	"py-random-secret": {
		match: []string{`token = "".join(random.choice(alphabet) for _ in range(32))`},
		safe:  []string{`token = secrets.token_urlsafe(32)`, `delay = random.uniform(0, 1)`},
	},
	"js-math-random-secret": {
		match: []string{`const sessionId = Math.random().toString(36).slice(2)`},
		safe:  []string{`const jitter = Math.random() * 100`},
	},
	"py-jwt-no-verify": {
		match: []string{`claims = jwt.decode(token, verify=False)`, `claims = jwt.decode(token, options={"verify_signature": False})`, `claims = jwt.decode(token, key, algorithms=["none"])`},
		safe:  []string{`claims = jwt.decode(token, key, algorithms=["HS256"])`},
	},
	"js-jwt-decode": {
		match: []string{`const claims = jwt.decode(token)`},
		safe:  []string{`const claims = jwt.verify(token, key, { algorithms: ["HS256"] })`},
	},
	"go-jwt-parse-unverified": {
		match: []string{`token, _, err := parser.ParseUnverified(raw, claims)`},
		safe:  []string{`token, err := jwt.ParseWithClaims(raw, claims, keyFunc)`},
	},
	"cors-wildcard-with-credentials": {
		match: []string{"w.Header().Set(\"Access-Control-Allow-Origin\", \"*\")\nw.Header().Set(\"Access-Control-Allow-Credentials\", \"true\")"},
		safe:  []string{`w.Header().Set("Access-Control-Allow-Origin", "*")`, "w.Header().Set(\"Access-Control-Allow-Origin\", \"https://app.example.com\")\nw.Header().Set(\"Access-Control-Allow-Credentials\", \"true\")"},
	},
	"cors-reflected-origin": {
		match: []string{`w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))`},
		safe:  []string{`w.Header().Set("Access-Control-Allow-Origin", "https://app.example.com")`},
	},
	"py-flask-debug": {
		match: []string{`app.run(debug=True)`},
		safe:  []string{`app.run(debug=False)`, `app.run()`},
	},
	"py-flask-debug-public": {
		match: []string{`app.run(host="0.0.0.0", port=5000, debug=True)`, `app.run(debug=True, host='0.0.0.0')`},
		safe:  []string{`app.run(host="0.0.0.0", port=5000)`, `app.run(debug=True)`},
	},
	"py-django-debug": {
		match: []string{`DEBUG = True`},
		safe:  []string{`DEBUG = False`, `DEBUG = os.environ.get("DEBUG") == "1"`},
	},
	"py-render-template-string": {
		match: []string{`return render_template_string(template)`, `return render_template_string("<h1>" + name + "</h1>")`},
		safe:  []string{`return render_template_string("<h1>{{ name }}</h1>", name=name)`, `return render_template("index.html", name=name)`},
	},
	"py-jinja-template-request": {
		match: []string{`t = Template(request.args.get("tpl"))`},
		safe:  []string{`t = Template("Hello {{ name }}")`},
	},
	"go-template-html-request": {
		match: []string{`data.Bio = template.HTML(r.FormValue("bio"))`},
		safe:  []string{`data.Bio = template.HTMLEscapeString(r.FormValue("bio"))`, `data.Banner = template.HTML("<b>hi</b>")`},
	},
	"js-dangerously-set-inner-html": {
		match: []string{`return <div dangerouslySetInnerHTML={{ __html: props.bio }} />`},
		safe:  []string{`return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(props.bio) }} />`, `return <div>{props.bio}</div>`},
	},
	"js-inner-html": {
		match: []string{`el.innerHTML = "<b>" + name + "</b>"`, `el.innerHTML = userHtml;`},
		safe:  []string{`el.innerHTML = "";`, `el.textContent = name;`, `if (el.innerHTML === "") return;`},
	},
	"js-document-write": {
		match: []string{`document.write(location.hash)`},
		safe:  []string{`document.write("<p>static</p>")`},
	},
	"py-xml-external-entities": {
		match: []string{`parser = etree.XMLParser()`, `parser = lxml.etree.XMLParser(resolve_entities=True)`},
		safe:  []string{`parser = etree.XMLParser(resolve_entities=False, no_network=True)`},
	},
	"js-xml-external-entities": {
		match: []string{`const doc = libxml.parseXml(body, { noent: true })`},
		safe:  []string{`const doc = libxml.parseXml(body, { noent: false })`},
	},
	"py-redirect-request": {
		match: []string{`return redirect(request.args.get("next"))`},
		safe:  []string{`return redirect(url_for("index"))`},
	},
	"go-redirect-request": {
		match: []string{`http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)`},
		safe:  []string{`http.Redirect(w, r, "/login", http.StatusFound)`},
	},
	"js-redirect-request": {
		match: []string{`res.redirect(req.query.next)`, `res.redirect(302, req.query.next)`},
		safe:  []string{`res.redirect("/login")`},
	},
}

func TestCodeRulesMatchAndSkip(t *testing.T) {
	for i := range codeRules {
		r := codeRules[i]
		t.Run(r.ID, func(t *testing.T) {
			c, ok := ruleCases[r.ID]
			if !ok || len(c.match) == 0 || len(c.safe) == 0 {
				t.Fatalf("rule %s needs at least one matching and one safe snippet in ruleCases", r.ID)
			}
			for _, src := range c.match {
				if got := matchRules([]*Rule{&r}, r.Langs[0], "f", src); len(got) == 0 {
					t.Errorf("should match: %s", src)
				}
			}
			for _, src := range c.safe {
				if got := matchRules([]*Rule{&r}, r.Langs[0], "f", src); len(got) != 0 {
					t.Errorf("should not match: %s", src)
				}
			}
		})
	}
	for id := range ruleCases {
		found := false
		for _, r := range codeRules {
			found = found || r.ID == id
		}
		if !found {
			t.Errorf("ruleCases has an entry for unknown rule %s", id)
		}
	}
}

func TestCodeRulesMetadata(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range codeRules {
		if seen[r.ID] {
			t.Errorf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
		if _, ok := finding.DefaultVector(r.Class); !ok {
			t.Errorf("%s: class %q has no default vector", r.ID, r.Class)
		}
		if !strings.HasPrefix(r.CWE, "CWE-") || len(r.CWE) < 5 {
			t.Errorf("%s: CWE %q is not set", r.ID, r.CWE)
		}
		if r.Detail == "" || r.Fix == "" || r.Title == "" || strings.HasSuffix(r.Title, ".") {
			t.Errorf("%s: Title (no trailing period), Detail and Fix must be set", r.ID)
		}
		switch r.Severity {
		case "critical", "high", "medium", "low":
		default:
			t.Errorf("%s: severity %q", r.ID, r.Severity)
		}
		if len(r.Langs) == 0 || r.Pattern == nil {
			t.Errorf("%s: Langs and Pattern must be set", r.ID)
		}
		for _, text := range []string{r.Title, r.Detail, r.Fix} {
			for _, c := range text {
				if c > 127 {
					t.Errorf("%s: non-ASCII text %q", r.ID, text)
				}
			}
		}
	}
}

func TestCodeSeederRun(t *testing.T) {
	root, files := writeTree(t, map[string]string{
		// CRLF line endings and a directory name with a space.
		"my app/db.py": "import sqlite3\r\n\r\ndef find(cur, name):\r\n    # cur.execute(f\"SELECT {name}\")\r\n    cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\r\n",
		// Test code is not attack surface.
		"my app/test_db.py":         "cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
		"tests/helpers.py":          "os.system(cmd)\n",
		"web/handler_test.go":       "package web\nvar h = md5.New()\n",
		"web/__tests__/a.js":        "eval(x)\n",
		"web/app.spec.ts":           "eval(x)\n",
		"web/app.test.js":           "eval(x)\n",
		"web/handler.go":            "package web\n\nfunc h() {\n\t// h := md5.New()\n\th := md5.New()\n\t_ = h\n}\n",
		"web/notes.txt":             "eval(x) and md5.New() in prose\n",
		"web/client.ts":             "const t = eval(input)\n",
		"web/long.js":               "const v = eval(input) // " + strings.Repeat("x", 400) + "\n",
		"web/secret.py":             "os.system(\"deploy --token " + "gh" + "p_" + strings.Repeat("a1B2", 9) + " \" + host)\n",
		"web/__tests__/nested/b.js": "eval(x)\n",
	})
	leads, err := codeSeeder{rules: codeRules}.Run(context.Background(), root, files)
	if err != nil {
		t.Fatal(err)
	}
	type key struct {
		file string
		line int
		rule string
	}
	got := map[key]Lead{}
	for _, l := range leads {
		got[key{l.File, l.Line, l.RuleID}] = l
	}
	want := []key{
		{"my app/db.py", 5, "py-sql-fstring"},
		{"web/handler.go", 5, "go-weak-hash"},
		{"web/client.ts", 1, "js-eval"},
		{"web/long.js", 1, "js-eval"},
		{"web/secret.py", 1, "py-os-system"},
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing lead %+v; got %v", k, ruleIDs(leads))
		}
	}
	if len(leads) != len(want) {
		for _, l := range leads {
			t.Logf("lead %s:%d %s", l.File, l.Line, l.RuleID)
		}
		t.Errorf("got %d leads, want %d", len(leads), len(want))
	}
	l := got[key{"my app/db.py", 5, "py-sql-fstring"}]
	if l.Snippet != `cur.execute(f"SELECT * FROM users WHERE name = '{name}'")` {
		t.Errorf("snippet = %q (CRLF must be normalized and the line trimmed)", l.Snippet)
	}
	if l.Class != "sql-injection" || l.Surface != finding.SurfaceCode || len(l.CWE) != 1 || l.CWE[0] != "CWE-89" || l.Severity != "high" {
		t.Errorf("unexpected lead fields: %+v", l)
	}
	if l.ID != "" || l.Source != "" {
		t.Errorf("seeders must leave ID and Source to RunAll: %+v", l)
	}
	if n := len([]rune(got[key{"web/long.js", 1, "js-eval"}].Snippet)); n != 200 {
		t.Errorf("long snippet has %d chars, want 200", n)
	}
	if s := got[key{"web/secret.py", 1, "py-os-system"}].Snippet; strings.Contains(s, "a1B2a1B2") || !strings.Contains(s, "[REDACTED:github-token:") {
		t.Errorf("snippet was not redacted: %q", s)
	}
}

func TestCodeSeederHonorsCancel(t *testing.T) {
	root, files := writeTree(t, map[string]string{"a.py": "os.system(cmd)\n"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (codeSeeder{rules: codeRules}).Run(ctx, root, files); err == nil {
		t.Error("want an error from a cancelled context")
	}
}

func TestSeederSets(t *testing.T) {
	var names []string
	for _, s := range All() {
		names = append(names, s.Name())
		if ok, note := s.Available(); !ok && note == "" {
			t.Errorf("%s is unavailable without a note", s.Name())
		}
	}
	want := "builtin-code,builtin-secrets,builtin-infra,semgrep,gitleaks,osv-scanner,trivy,hadolint"
	if got := strings.Join(names, ","); got != want {
		t.Errorf("All() = %s, want %s", got, want)
	}
	if len(Builtin()) != 3 || len(External()) != 5 {
		t.Errorf("Builtin() has %d seeders and External() has %d", len(Builtin()), len(External()))
	}
	for _, s := range Builtin() {
		if ok, _ := s.Available(); !ok {
			t.Errorf("built-in seeder %s must always be available", s.Name())
		}
	}
}

// Comment handling depends on the language, and Exclude and Require see
// only the code part of a line.
func TestCodeRulesCommentHandling(t *testing.T) {
	byID := map[string]*Rule{}
	for i := range codeRules {
		byID[codeRules[i].ID] = &codeRules[i]
	}
	cases := []struct {
		rule, lang, src string
		want            bool
	}{
		// A statement that starts with * or # is code, not a comment.
		{"go-tls-skip-verify", "go", "\t*cfg = tls.Config{InsecureSkipVerify: true}", true},
		{"go-file-from-request", "go", "\t*out, err = os.ReadFile(r.URL.Query().Get(\"f\"))", true},
		{"js-math-random-secret", "javascript", "  #token = Math.random().toString(36)", true},
		{"js-child-process-exec", "javascript", "  #run(cmd) { return exec(\"sh \" + cmd) }", true},
		// A word in a trailing comment does not hide the lead.
		{"py-yaml-load", "python", "cfg = yaml.unsafe_load(f)  # SafeLoader is too strict", true},
		{"py-tls-verify-false", "python", "r = requests.get(url, verify=False)  # jwt.decode( elsewhere", true},
		{"py-flask-debug", "python", "app.run(host='127.0.0.1', debug=True)  # not 0.0.0.0", true},
		// A trailing comment does not turn a harmless literal into a lead.
		{"js-inner-html", "javascript", "el.innerHTML = '';  // reset", false},
		// Comments themselves never match, in each language's own syntax.
		{"go-tls-skip-verify", "go", "// cfg := tls.Config{InsecureSkipVerify: true}", false},
		{"go-tls-skip-verify", "go", "/*\n * cfg := tls.Config{InsecureSkipVerify: true}\n */", false},
		{"go-tls-skip-verify", "go", "x := 1 // tls.Config{InsecureSkipVerify: true}", false},
		{"py-tls-verify-false", "python", "# r = requests.get(url, verify=False)", false},
		// A comment marker inside a string literal is not a comment.
		{"js-child-process-exec", "javascript", "exec(\"curl http://\" + host + \"/x\")", true},
		// A block comment ends where it ends: the code after it is seen.
		{"go-tls-skip-verify", "go", "/* note */ cfg := tls.Config{InsecureSkipVerify: true}", true},
		// "/*" inside a regular expression literal does not start a comment.
		{"js-child-process-exec", "javascript", "const re = /\\/*$/\nexec(\"sh \" + cmd)", true},
	}
	for _, c := range cases {
		r, ok := byID[c.rule]
		if !ok {
			t.Errorf("unknown rule %s", c.rule)
			continue
		}
		got := len(matchRules([]*Rule{r}, c.lang, "f", c.src)) > 0
		if got != c.want {
			t.Errorf("%s on %q: lead=%v, want %v", c.rule, c.src, got, c.want)
		}
	}
}
