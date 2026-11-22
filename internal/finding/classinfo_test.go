package finding

import (
	"regexp"
	"strings"
	"testing"
)

var owaspPattern = regexp.MustCompile(`^A(0[1-9]|10):2021 `)

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func checkList(t *testing.T, class, field string, items []string, minLen, maxLen int) {
	t.Helper()
	if len(items) < minLen || len(items) > maxLen {
		t.Errorf("%s: %s has %d items, want %d to %d", class, field, len(items), minLen, maxLen)
	}
	for _, s := range items {
		switch {
		case strings.TrimSpace(s) == "":
			t.Errorf("%s: %s has an empty item", class, field)
		case !isASCII(s):
			t.Errorf("%s: %s item %q is not ASCII", class, field, s)
		case strings.HasSuffix(s, "."):
			t.Errorf("%s: %s item %q ends with a period", class, field, s)
		}
	}
}

func TestInfoCoversEveryClass(t *testing.T) {
	for class := range classVectors {
		ci := Info(class)
		if ci.Name == "" || ci.Name == class {
			t.Errorf("%s: missing human Name (got %q)", class, ci.Name)
		}
		if !isASCII(ci.Name) {
			t.Errorf("%s: Name %q is not ASCII", class, ci.Name)
		}
		checkList(t, class, "OWASP", ci.OWASP, 1, 3)
		for _, o := range ci.OWASP {
			if !owaspPattern.MatchString(o) {
				t.Errorf("%s: OWASP %q does not match %s", class, o, owaspPattern)
			}
		}
		checkList(t, class, "Preconditions", ci.Preconditions, 1, 2)
		checkList(t, class, "Steps", ci.Steps, 2, 4)
		checkList(t, class, "ChainsInto", ci.ChainsInto, 1, 2)
		checkList(t, class, "Gains", ci.Gains, 1, 3)
		if ci.Fix == "" {
			t.Errorf("%s: empty Fix", class)
		}
		if !isASCII(ci.Fix) {
			t.Errorf("%s: Fix is not ASCII", class)
		}
		if !strings.HasSuffix(ci.Fix, ".") {
			t.Errorf("%s: Fix does not end with a period", class)
		}
	}
}

func TestInfoHasNoOrphanClasses(t *testing.T) {
	for class := range classInfo {
		if _, ok := classVectors[class]; !ok {
			t.Errorf("classInfo has %q, which is not a key of classVectors", class)
		}
	}
}

func TestInfoUnknownClass(t *testing.T) {
	ci := Info("made-up")
	if ci.Name != "made-up" {
		t.Errorf("Name = %q, want %q", ci.Name, "made-up")
	}
	if len(ci.OWASP) != 0 || len(ci.Preconditions) != 0 || len(ci.Steps) != 0 ||
		len(ci.ChainsInto) != 0 || len(ci.Gains) != 0 {
		t.Errorf("unknown class has non-empty slices: %+v", ci)
	}
	if ci.Fix != "" {
		t.Errorf("Fix = %q, want empty", ci.Fix)
	}
}
