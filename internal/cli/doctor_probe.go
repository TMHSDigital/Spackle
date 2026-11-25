package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TMHSDigital/spackle/internal/config"
	"github.com/TMHSDigital/spackle/internal/llm"
)

// doctorProbe checks one configured model: that its provider can be built
// (key present, offline rule satisfied) and that a free round-trip to the
// provider accepts the key and knows the model.
func doctorProbe(ctx context.Context, cfg config.Config, stage string, m config.Model) []check {
	label := m.Provider + " " + m.Model
	name := "model (" + stage + ")"
	prov, err := newProvider(m, llm.Options{Offline: cfg.Offline})
	if err != nil {
		return []check{{"Model", name, "fail", label + ": " + err.Error()}}
	}
	prober, ok := prov.(llm.Prober)
	if !ok {
		return []check{{"Model", name, "ok", label + " (configuration only; this provider has no free check)"}}
	}
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	note, warnings, err := prober.Probe(pctx)
	if err != nil {
		msg := label + ": " + err.Error()
		var apiErr *llm.APIError
		if errors.As(err, &apiErr) && apiErr.Hint() != "" {
			msg += ". " + apiErr.Hint()
		}
		return []check{{"Model", name, "fail", msg}}
	}
	where := "remote"
	if prov.Local() {
		where = "local, nothing leaves this machine"
	}
	out := []check{{"Model", name, "ok", fmt.Sprintf("%s (%s)%s", label, where, prefixed(note))}}
	for _, w := range warnings {
		out = append(out, check{"Model", name, "warn", w})
	}
	if _, priced := llm.NewPricer(llm.PricesFromConfig(cfg.Pricing)).Lookup(m.Model); !priced && !prov.Local() {
		out = append(out, check{"Model", name, "warn", "no price is known for this model, so spend cannot be capped in dollars; the token cap still applies. Add [pricing.\"" + m.Model + "\"] to spackle.toml"})
	}
	return out
}

// newProvider is llm.New. Tests replace it to probe a remote provider
// without sending a request to another machine.
var newProvider = llm.New

func prefixed(note string) string {
	if note == "" {
		return ""
	}
	return ": " + note
}
