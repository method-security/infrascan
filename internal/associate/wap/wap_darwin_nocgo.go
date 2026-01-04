//go:build darwin && !cgo

package wap

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Method-Security/infrascan/generated/go/associate"
)

// findWirelessInterface finds the default wireless interface on macOS without CGO.
func findWirelessInterface(ctx context.Context) (string, error) {
	// Use networksetup to list hardware ports
	cmd := exec.Command("networksetup", "-listallhardwareports")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to list hardware ports: %w", err)
	}

	// Parse output to find Wi-Fi interface
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if strings.Contains(line, "Wi-Fi") || strings.Contains(line, "AirPort") {
			// Next line should contain the device
			if i+1 < len(lines) {
				deviceLine := lines[i+1]
				if strings.HasPrefix(deviceLine, "Device: ") {
					return strings.TrimPrefix(deviceLine, "Device: "), nil
				}
			}
		}
	}

	// Default to en0 which is typically the Wi-Fi interface
	return "en0", nil
}

// getCurrentConnection returns the current WiFi connection info without CGO.
// getConnectionProfileName returns the network profile name on macOS.
// On macOS, returns SSID for compatibility (no separate profile concept).
func getConnectionProfileName(ctx context.Context, interfaceName string) string {
	ssid, _, connected := getCurrentConnection(ctx, interfaceName)
	if connected {
		return ssid
	}
	return ""
}

func getCurrentConnection(ctx context.Context, interfaceName string) (ssid string, bssid string, connected bool) {
	iface := interfaceName
	if iface == "" {
		iface = "en0"
	}

	// Use networksetup to get current network
	cmd := exec.Command("networksetup", "-getairportnetwork", iface)
	output, err := cmd.Output()
	if err != nil {
		return "", "", false
	}

	// Parse output: "Current Wi-Fi Network: <SSID>"
	outputStr := strings.TrimSpace(string(output))
	if strings.HasPrefix(outputStr, "Current Wi-Fi Network: ") {
		ssid = strings.TrimPrefix(outputStr, "Current Wi-Fi Network: ")
		return ssid, "", true
	}

	return "", "", false
}

// getSignalQuality returns the RSSI for a target network without CGO.
func getSignalQuality(ctx context.Context, interfaceName string, targetSSID string, targetBSSID string) int {
	// airport command can get signal info
	cmd := exec.Command("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	// Parse agrCtlRSSI from output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "agrCtlRSSI:") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				var rssi int
				fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &rssi)
				return rssi
			}
		}
	}

	return 0
}

// disconnectFromNetwork disconnects from the current WiFi network without CGO.
func disconnectFromNetwork(ctx context.Context, interfaceName string) error {
	iface := interfaceName
	if iface == "" {
		iface = "en0"
	}

	// Turn off Wi-Fi and then back on to disconnect
	cmd := exec.Command("networksetup", "-setairportpower", iface, "off")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to turn off WiFi: %w", err)
	}

	return nil
}

// reconnectToOriginalNetwork reconnects to the original WiFi network without CGO.
func reconnectToOriginalNetwork(ctx context.Context, interfaceName string, original *associate.OriginalNetworkState) error {
	if original == nil || !original.WasConnected {
		return nil
	}

	iface := interfaceName
	if iface == "" {
		iface = "en0"
	}

	// Turn Wi-Fi back on
	cmd := exec.Command("networksetup", "-setairportpower", iface, "on")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to turn on WiFi: %w", err)
	}

	// Wait a moment for WiFi to initialize
	// macOS should auto-connect to known networks

	return nil
}

// connectToNetwork performs connection attempt without CGO.
func connectToNetwork(
	ctx context.Context,
	interfaceName string,
	targetSSID string,
	targetBSSID string,
	cred *associate.TestClientProfile,
	timeout int,
) *ConnectionResult {
	result := NewConnectionResult()
	result.WithError(associate.AssociationOutcomeDriverError,
		"Direct WiFi connection requires CGO on macOS. Please build with CGO enabled.")
	return result
}

// detectNetworkSecurity detects the security type of a target wireless network without CGO.
// Uses the airport command to scan for networks and determine security.
func detectNetworkSecurity(ctx context.Context, interfaceName string, targetSSID string, targetBSSID string) NetworkSecurityType {
	// Use airport command to scan
	cmd := exec.Command("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s")
	output, err := cmd.Output()
	if err != nil {
		return NetworkSecurityUnknown
	}

	// Parse output - format is:
	// SSID BSSID RSSI CHANNEL HT CC SECURITY (with dashes as separator)
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // Skip header line
		}

		// Parse fields - SSID can have spaces, so parse from the right
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}

		// Security is the last field
		security := strings.ToUpper(fields[len(fields)-1])

		// BSSID is typically in the format XX:XX:XX:XX:XX:XX, search for it
		bssid := ""
		for _, f := range fields {
			if len(f) == 17 && strings.Count(f, ":") == 5 {
				bssid = strings.ToUpper(f)
				break
			}
		}

		// SSID could be the first field or combined fields before BSSID
		ssid := fields[0]

		// Match by SSID or BSSID
		matchSSID := targetSSID != "" && ssid == targetSSID
		matchBSSID := targetBSSID != "" && strings.EqualFold(bssid, targetBSSID)

		if matchSSID || matchBSSID {
			return parseAirportSecurityType(security)
		}
	}

	return NetworkSecurityUnknown
}

// parseAirportSecurityType parses the security string from airport -s output.
func parseAirportSecurityType(security string) NetworkSecurityType {
	if security == "NONE" || security == "--" || security == "" {
		return NetworkSecurityOpen
	}

	// Check for Enterprise
	if strings.Contains(security, "802.1X") || strings.Contains(security, "ENTERPRISE") {
		return NetworkSecurityEAP
	}

	// WPA/WPA2/WPA3 without Enterprise = PSK
	if strings.Contains(security, "WPA") {
		return NetworkSecurityPSK
	}

	// WEP also requires a key
	if strings.Contains(security, "WEP") {
		return NetworkSecurityPSK
	}

	return NetworkSecurityUnknown
}

