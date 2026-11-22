package cli

import (
	"context"
	"fmt"

	"github.com/TMHSDigital/spackle/internal/config"
)

// doctorProbe checks one configured model. It verifies the API key variable
// is present; the live round-trip is wired in with the providers.
func doctorProbe(_ context.Context, _ config.Config, stage string, m config.Model) []check {
	label := m.Provider + " " + m.Model
	name := "model (" + stage + ")"
	if env, ok := keyPresent(m); !ok {
		return []check{{"Model", name, "fail", fmt.Sprintf("%s: environment variable %s is not set. Export it, or set api_key_env to the variable that holds the key", label, env)}}
	}
	return []check{{"Model", name, "ok", label}}
}
