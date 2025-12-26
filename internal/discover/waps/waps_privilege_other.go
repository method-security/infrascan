//go:build !linux && !darwin && !windows

package waps

// isUnixRoot is a stub for unsupported platforms.
func isUnixRoot() bool {
	return false
}

// isWindowsAdmin is a stub for unsupported platforms.
func isWindowsAdmin() bool {
	return false
}
