//go:build windows

package waps

import (
	"golang.org/x/sys/windows"
)

// isUnixRoot is a stub for Windows platform.
func isUnixRoot() bool { return false }

// isWindowsAdmin checks if the current process has administrator privileges.
func isWindowsAdmin() bool {
	// Create a SID for the built-in administrators group
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}

	// Token(0) = current process token
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

// Optional: fallback using shell32.dll (usually unnecessary if IsMember works)
func isWindowsAdminFallback() bool {
	mod := windows.NewLazySystemDLL("shell32.dll")
	proc := mod.NewProc("IsUserAnAdmin")
	ret, _, _ := proc.Call()
	return ret != 0
}
