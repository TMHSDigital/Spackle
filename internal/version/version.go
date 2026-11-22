// Package version holds build metadata set by the linker at release time.
package version

// These are overridden with -ldflags "-X ..." by the release build.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
