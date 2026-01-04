//go:build !darwin && !linux && !windows

package wap

import (
	"context"
	"fmt"
	"runtime"

	"github.com/Method-Security/infrascan/generated/go/connect"
)

// findWirelessInterface is not supported on this platform.
func findWirelessInterface(ctx context.Context) (string, error) {
	return "", fmt.Errorf("wireless operations not supported on %s", runtime.GOOS)
}

// getCurrentConnection is not supported on this platform.
func getCurrentConnection(ctx context.Context, interfaceName string) (ssid string, bssid string, connected bool) {
	return "", "", false
}

// getConnectionProfileName is not supported on this platform.
func getConnectionProfileName(ctx context.Context, interfaceName string) string {
	return ""
}

// getSignalQuality is not supported on this platform.
func getSignalQuality(ctx context.Context, interfaceName string, targetSSID string, targetBSSID string) int {
	return 0
}

// disconnectFromNetwork is not supported on this platform.
func disconnectFromNetwork(ctx context.Context, interfaceName string) error {
	return fmt.Errorf("wireless operations not supported on %s", runtime.GOOS)
}

// reconnectToOriginalNetwork is not supported on this platform.
func reconnectToOriginalNetwork(ctx context.Context, interfaceName string, original *connect.OriginalNetworkState) error {
	return fmt.Errorf("wireless operations not supported on %s", runtime.GOOS)
}

// connectToNetwork is not supported on this platform.
func connectToNetwork(
	ctx context.Context,
	interfaceName string,
	targetSSID string,
	targetBSSID string,
	cred *connect.TestClientProfile,
	timeout int,
) *ConnectionResult {
	result := NewConnectionResult()
	result.WithError(connect.ConnectionOutcomeDriverError,
		fmt.Sprintf("wireless operations not supported on %s", runtime.GOOS))
	return result
}

// detectNetworkSecurity is not supported on this platform.
func detectNetworkSecurity(ctx context.Context, interfaceName string, targetSSID string, targetBSSID string) NetworkSecurityType {
	return NetworkSecurityUnknown
}
