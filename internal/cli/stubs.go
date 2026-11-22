package cli

func runScan(env Env, _ []string) int   { return notYet(env, "scan") }
func runDebug(env Env, _ []string) int  { return notYet(env, "debug") }
func runVerify(env Env, _ []string) int { return notYet(env, "verify") }
func runReport(env Env, _ []string) int { return notYet(env, "report") }
func runDoctor(env Env, _ []string) int { return notYet(env, "doctor") }
func runMCP(env Env, _ []string) int    { return notYet(env, "mcp") }

// Keep the shared flag helpers referenced until the first real command lands.
var (
	_ = newFlagSet
	_ = flagExit
)
