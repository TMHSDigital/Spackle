package seed

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/TMHSDigital/spackle/internal/walk"
)

// eachFile gives the same leads in the same order however the workers are
// scheduled, and reports the first error in file order.
func TestEachFileIsDeterministic(t *testing.T) {
	files := make([]walk.File, 200)
	for i := range files {
		files[i] = walk.File{Rel: fmt.Sprintf("f%03d.py", i)}
	}
	check := func(f walk.File) ([]Lead, error) {
		if f.Rel == "f007.py" || f.Rel == "f151.py" {
			return nil, errors.New("cannot read " + f.Rel)
		}
		if strings.HasSuffix(f.Rel, "0.py") {
			return nil, nil
		}
		return []Lead{{File: f.Rel, Line: 1}, {File: f.Rel, Line: 2}}, nil
	}
	for round := 0; round < 5; round++ {
		leads, err := eachFile(context.Background(), "test", files, check)
		if err == nil || err.Error() != "cannot read f007.py" {
			t.Fatalf("err = %v, want the first error in file order", err)
		}
		if len(leads) != (200-20-2)*2 {
			t.Fatalf("leads = %d", len(leads))
		}
		for i := 1; i < len(leads); i++ {
			a, b := leads[i-1], leads[i]
			if a.File > b.File || (a.File == b.File && a.Line > b.Line) {
				t.Fatalf("leads are not in file order at %d: %s:%d then %s:%d", i, a.File, a.Line, b.File, b.Line)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := eachFile(ctx, "test", files, check); err == nil || !strings.Contains(err.Error(), "stopped early") {
		t.Fatalf("a cancelled run returned %v", err)
	}
	if leads, err := eachFile(context.Background(), "test", nil, check); err != nil || len(leads) != 0 {
		t.Fatalf("no files: leads=%d err=%v", len(leads), err)
	}
}
