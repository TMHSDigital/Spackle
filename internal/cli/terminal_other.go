//go:build !windows

package cli

import "os"

// isNullDevice reports whether the character device f, with file info st,
// is the null device.
func isNullDevice(_ *os.File, st os.FileInfo) bool {
	null, err := os.Stat(os.DevNull)
	return err == nil && os.SameFile(st, null)
}
