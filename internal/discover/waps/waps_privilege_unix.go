//go:build linux || darwin

package waps

import (
	"os"
)

// isUnixRoot checks if the current process is running as root (UID 0).
func isUnixRoot() bool {
	return os.Getuid() == 0
}

