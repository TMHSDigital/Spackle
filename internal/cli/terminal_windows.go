package cli

import (
	"os"
	"syscall"
)

// isNullDevice reports whether the character device f is something other
// than a console, which on Windows means NUL: only a console handle has a
// console mode.
func isNullDevice(f *os.File, _ os.FileInfo) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) != nil
}
