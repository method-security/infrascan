// Package waps in discover handles wireless access point discovery via passive 802.11 reconnaissance.
package waps

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/Method-Security/infrascan/generated/go/discover"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// DiscoverWaps performs wireless access point discovery using passive monitoring
// where possible, falling back to system utilities for compatibility.
// Returns a report containing all observed access points and any errors encountered.
func DiscoverWaps(ctx context.Context, config discover.DiscoverWapsConfig) (*discover.DiscoverWapsReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	interfaceName := ""
	if config.Interface != nil {
		interfaceName = *config.Interface
	}

	timeout := 30
	if config.Timeout != nil {
		timeout = *config.Timeout
	}

	passive := false
	if config.Passive != nil {
		passive = *config.Passive
	}

	log.Info("Starting wireless access point discovery",
		svc1log.SafeParam("interface", interfaceName),
		svc1log.SafeParam("timeout", timeout),
		svc1log.SafeParam("passive", passive),
		svc1log.SafeParam("os", runtime.GOOS))

	startTime := time.Now()

	// Check if passive mode is requested
	if passive {
		if err := checkPassiveModeSupport(ctx, interfaceName); err != nil {
			log.Warn("Passive mode not available",
				svc1log.SafeParam("error", err.Error()),
				svc1log.SafeParam("os", runtime.GOOS))
			errors = append(errors, err.Error())

			// Return early with error - passive mode was explicitly requested but not available
			endTime := time.Now()
			return &discover.DiscoverWapsReport{
				Config: &config,
				Result: &discover.DiscoverWapsResult{
					ScanMetadata: &discover.ScanMetadata{
						StartTime:   &startTime,
						EndTime:     &endTime,
						PassiveMode: ptr(false),
					},
					Observations: nil,
				},
				Errors: errors,
			}, fmt.Errorf("passive mode requested but not available: %w", err)
		}
	}

	// Perform platform-specific scanning
	var observations []*discover.PassiveWirelessObservation
	var channelsScanned []int
	var scanErr error

	if passive {
		// Passive scanning - uses monitor mode packet capture
		observations, channelsScanned, scanErr = scanPassive(ctx, interfaceName, timeout)
	} else {
		// Active scanning - uses system utilities
		switch runtime.GOOS {
		case "darwin":
			observations, channelsScanned, scanErr = scanDarwin(ctx, interfaceName, timeout)
		case "linux":
			observations, channelsScanned, scanErr = scanLinux(ctx, interfaceName, timeout)
		case "windows":
			observations, channelsScanned, scanErr = scanWindows(ctx, interfaceName, timeout)
		default:
			errors = append(errors, "unsupported operating system: "+runtime.GOOS)
		}
	}

	if scanErr != nil {
		errors = append(errors, scanErr.Error())
	}

	// Filter by target SSID if specified
	if config.TargetSsid != nil && *config.TargetSsid != "" {
		observations = filterBySSID(observations, *config.TargetSsid)
	}

	// Enrich observations with OUI vendor lookup
	for _, obs := range observations {
		enrichWithVendorInfo(obs)
	}

	endTime := time.Now()

	// Build scan metadata
	scanMetadata := &discover.ScanMetadata{
		StartTime:       &startTime,
		EndTime:         &endTime,
		ChannelsScanned: channelsScanned,
		PassiveMode:     &passive,
	}

	// Create the report
	report := &discover.DiscoverWapsReport{
		Config: &config,
		Result: &discover.DiscoverWapsResult{
			ScanMetadata: scanMetadata,
			Observations: observations,
		},
		Errors: errors,
	}

	log.Info("Completed wireless access point discovery",
		svc1log.SafeParam("interface", interfaceName),
		svc1log.SafeParam("aps_found", len(observations)),
		svc1log.SafeParam("error_count", len(errors)),
		svc1log.SafeParam("duration_seconds", endTime.Sub(startTime).Seconds()))

	return report, nil
}

// filterBySSID filters observations to only include those matching the target SSID.
func filterBySSID(observations []*discover.PassiveWirelessObservation, targetSSID string) []*discover.PassiveWirelessObservation {
	var filtered []*discover.PassiveWirelessObservation
	for _, obs := range observations {
		if obs.Ssid != nil && *obs.Ssid == targetSSID {
			filtered = append(filtered, obs)
		}
	}
	return filtered
}

// enrichWithVendorInfo adds vendor fingerprint information based on the BSSID OUI.
func enrichWithVendorInfo(obs *discover.PassiveWirelessObservation) {
	if obs.Bssid == "" {
		return
	}

	oui := extractOUI(obs.Bssid)
	vendorName := lookupOUI(oui)

	obs.VendorFingerprint = &discover.VendorFingerprint{
		Oui:        &oui,
		VendorName: vendorName,
	}
}

// extractOUI extracts the first 3 bytes (OUI) from a MAC address.
// Input format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
func extractOUI(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	// Return first 8 characters (XX:XX:XX)
	return mac[:8]
}

// channelToFrequency converts a WiFi channel number to frequency in MHz.
func channelToFrequency(channel int) int {
	// 2.4 GHz band
	if channel >= 1 && channel <= 13 {
		return 2407 + (channel * 5)
	}
	if channel == 14 {
		return 2484
	}

	// 5 GHz band
	if channel >= 32 && channel <= 68 {
		return 5160 + ((channel - 32) * 5)
	}
	if channel >= 96 && channel <= 144 {
		return 5480 + ((channel - 96) * 5)
	}
	if channel >= 149 && channel <= 177 {
		return 5745 + ((channel - 149) * 5)
	}

	return 0
}

// ptr is a helper function to create a pointer to a value.
func ptr[T any](v T) *T {
	return &v
}

// checkPassiveModeSupport verifies that passive mode scanning is available on the current platform.
// Passive mode requires:
// - A wireless interface in monitor mode
// - Elevated privileges (root/administrator)
// - Platform-specific packet capture capabilities
func checkPassiveModeSupport(ctx context.Context, interfaceName string) error {
	log := svc1log.FromContext(ctx)

	switch runtime.GOOS {
	case "linux":
		// Linux supports passive mode via monitor mode interfaces
		// Requires: root privileges, interface in monitor mode, libpcap
		if interfaceName == "" {
			return fmt.Errorf("passive mode on Linux requires specifying a monitor mode interface (e.g., wlan0mon). " +
				"Enable monitor mode with: sudo airmon-ng start <interface>")
		}
		// Check if running as root
		if !isRunningAsRoot() {
			log.Warn("Passive mode requires root privileges on Linux")
			return fmt.Errorf("passive mode on Linux requires root privileges. Run with sudo")
		}
		// Note: Full implementation would check if interface is in monitor mode
		// and if libpcap is available. For now, we indicate it's not implemented.
		return fmt.Errorf("passive mode (monitor mode packet capture) is not yet implemented. " +
			"Currently supported: active scanning via 'iw' which emits probe requests")

	case "darwin":
		// macOS passive mode is complex - requires disabling Wi-Fi, using CoreWLAN with monitor mode
		// Apple has restricted monitor mode access in recent versions
		if !isRunningAsRoot() {
			return fmt.Errorf("passive mode on macOS requires root privileges. Run with sudo")
		}
		return fmt.Errorf("passive mode on macOS is not yet implemented. " +
			"macOS restricts monitor mode access. The airport utility always emits probe requests. " +
			"True passive scanning requires CoreWLAN with specific hardware support")

	case "windows":
		// Windows passive mode requires Npcap with monitor mode support and compatible hardware
		return fmt.Errorf("passive mode on Windows is not yet implemented. " +
			"Windows requires Npcap (or similar) with monitor mode support and compatible wireless hardware. " +
			"The netsh wlan command always emits probe requests")

	default:
		return fmt.Errorf("passive mode is not supported on %s", runtime.GOOS)
	}
}

// scanPassive performs true passive scanning using monitor mode packet capture.
// This function captures 802.11 beacon frames without emitting any RF transmissions.
func scanPassive(ctx context.Context, interfaceName string, timeout int) ([]*discover.PassiveWirelessObservation, []int, error) {
	// This is a placeholder for future implementation using gopacket/pcap
	// True passive scanning requires:
	// 1. Interface in monitor mode
	// 2. Packet capture library (libpcap/Npcap)
	// 3. 802.11 frame parsing
	//
	// Implementation would:
	// - Open pcap handle on monitor mode interface
	// - Set BPF filter for beacon frames (type 0, subtype 8)
	// - Capture packets for the specified timeout
	// - Parse 802.11 management frames and extract IEs
	// - Build PassiveWirelessObservation for each unique BSSID

	return nil, nil, fmt.Errorf("passive scanning not yet implemented - requires monitor mode packet capture")
}

// isRunningAsRoot checks if the current process has root/administrator privileges.
func isRunningAsRoot() bool {
	switch runtime.GOOS {
	case "linux", "darwin":
		// On Unix-like systems, check if UID is 0
		return isUnixRoot()
	case "windows":
		// On Windows, check for administrator privileges
		return isWindowsAdmin()
	default:
		return false
	}
}
