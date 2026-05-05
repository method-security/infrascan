//go:build linux || darwin

package waps

import (
	"os"
)

// isUnixRoot checks if the current process is running as root (UID 0).
func isUnixRoot() bool {
	return os.Getuid() == 0
}

// isWindowsAdmin is a stub for Unix platforms; the real implementation is in waps_privilege_windows.go.
func isWindowsAdmin() bool { return false } //nolint:unused

