package dast

import (
	"html"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Endpoint is something discovered on the target.
type Endpoint struct {
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Params []string `json:"params,omitempty"` // query or form field names, sorted
	Source string   `json:"source"`           // link|form|start
}

// Limits on what one page may add to the crawl. The page is untrusted: a
// target that returns a million links must not grow the run without bound.
const (
	maxLinksPerPage  = 500
	maxFormsPerPage  = 50
	maxFieldsPerForm = 40
	maxTargets       = 2000
)

// The page is read with regular expressions rather than an HTML parser on
// purpose: the crawl only needs URLs and field names, a tolerant match
// survives broken markup, and the standard library has no HTML parser.
const attrValue = `\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>]+))`

var (
	linkAttr   = regexp.MustCompile(`(?i)[\s"'](?:href|src)` + attrValue)
	formBlock  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)(?:</form\s*>|$)`)
	fieldTag   = regexp.MustCompile(`(?is)<(input|select|textarea)\b([^>]*)>`)
	actionAttr = regexp.MustCompile(`(?i)(?:^|[\s"'])action` + attrValue)
	methodAttr = regexp.MustCompile(`(?i)(?:^|[\s"'])method` + attrValue)
	nameAttr   = regexp.MustCompile(`(?i)(?:^|[\s"'])name` + attrValue)
	valueAttr  = regexp.MustCompile(`(?i)(?:^|[\s"'])value` + attrValue)
	typeAttr   = regexp.MustCompile(`(?i)(?:^|[\s"'])type` + attrValue)
)

// form is an HTML form found on a page.
type form struct {
	method string // GET or POST
	action *url.URL
	values url.Values // field name -> the value the page offered
}

// attr returns the value of one attribute inside a tag.
func attr(re *regexp.Regexp, tag string) (string, bool) {
	m := re.FindStringSubmatch(tag)
	if m == nil {
		return "", false
	}
	return html.UnescapeString(m[1] + m[2] + m[3]), true
}

// resolve turns an attribute value into an absolute http or https URL
// relative to the page. It returns nil for anything else (script and mail
// links, fragments, values that do not parse).
func resolve(base *url.URL, raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return nil
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	u := sendable(base.ResolveReference(ref))
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return nil
	}
	return u
}

// extract returns the links and forms on an HTML page, in document order.
func extract(body []byte, base *url.URL) ([]*url.URL, []form) {
	text := string(body)
	var links []*url.URL
	for _, m := range linkAttr.FindAllStringSubmatch(text, maxLinksPerPage) {
		if u := resolve(base, html.UnescapeString(m[1]+m[2]+m[3])); u != nil {
			links = append(links, u)
		}
	}
	var forms []form
	for _, m := range formBlock.FindAllStringSubmatch(text, maxFormsPerPage) {
		f := form{method: "GET", values: url.Values{}}
		if v, ok := attr(methodAttr, m[1]); ok && strings.TrimSpace(v) != "" {
			f.method = strings.ToUpper(strings.TrimSpace(v))
		}
		if f.method != "GET" && f.method != "POST" {
			// Not a method a form can submit with (for example "dialog").
			continue
		}
		action, _ := attr(actionAttr, m[1])
		if strings.TrimSpace(action) == "" {
			f.action = sendable(base)
		} else if f.action = resolve(base, action); f.action == nil {
			continue
		}
		if f.method == "GET" {
			// Submitting a GET form replaces the query of its action.
			f.action.RawQuery = ""
		}
		for _, field := range fieldTag.FindAllStringSubmatch(m[2], maxFieldsPerForm) {
			name, ok := attr(nameAttr, field[2])
			if !ok || name == "" {
				continue
			}
			value := ""
			if strings.EqualFold(field[1], "input") {
				kind, _ := attr(typeAttr, field[2])
				switch strings.ToLower(strings.TrimSpace(kind)) {
				case "submit", "button", "image", "reset", "file":
					continue
				}
				value, _ = attr(valueAttr, field[2])
			}
			if !f.values.Has(name) {
				f.values.Set(name, value)
			}
		}
		forms = append(forms, f)
	}
	return links, forms
}

// logoutWords mark URLs the crawl leaves alone so it does not delete the
// operator's data or end a session. The client itself holds no session; the
// words are about what a request could do on the target's side.
var logoutWords = []string{"logout", "signout", "delete", "remove", "destroy"}

func logoutLike(s string) bool {
	low := strings.ToLower(s)
	for _, w := range logoutWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}

// staticExt lists files that are neither pages nor endpoints with input.
var staticExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true, ".webp": true,
	".css": true, ".js": true, ".mjs": true, ".map": true, ".woff": true, ".woff2": true, ".ttf": true,
	".eot": true, ".mp3": true, ".mp4": true, ".webm": true, ".pdf": true, ".zip": true, ".gz": true,
}

func staticAsset(u *url.URL) bool {
	return u.RawQuery == "" && staticExt[strings.ToLower(path.Ext(u.Path))]
}

// paramNames returns the sorted field names.
func paramNames(v url.Values) []string {
	names := make([]string, 0, len(v))
	for name := range v {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// target is one endpoint the crawl found, with what is needed to request it.
type target struct {
	ep     Endpoint
	u      *url.URL   // scheme, host and path; for POST the action's own query too
	values url.Values // parameter name -> original value
	// fetched is set once the unmodified request has been answered.
	fetched bool
	// baseErrors holds the database error signatures in the unmodified
	// response. A probe proves nothing by showing an error that was
	// already there.
	baseErrors map[string]bool
}

func (t *target) key() string {
	return t.ep.Method + " " + t.u.Scheme + "://" + t.u.Host + t.u.Path + " " + strings.Join(t.ep.Params, "&")
}

// request returns the URL and body that submit values to the target.
func (t *target) request(values url.Values) (string, []byte, map[string]string) {
	u := *t.u
	if t.ep.Method == http.MethodGet {
		u.RawQuery = values.Encode()
		return u.String(), nil, nil
	}
	return u.String(), []byte(values.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
}

// newTarget builds a target from a URL (for links, with its query as the
// parameters) or from a form.
func newTarget(method string, u *url.URL, values url.Values, source string) *target {
	base := sendable(u)
	if values == nil {
		values = base.Query()
	}
	if method == "GET" {
		base.RawQuery = ""
	}
	p := base.Path
	if p == "" {
		p = "/"
	}
	return &target{
		ep:     Endpoint{Method: method, Path: p, Params: paramNames(values), Source: source},
		u:      base,
		values: values,
	}
}
