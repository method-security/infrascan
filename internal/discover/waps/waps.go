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
					Observations: []*discover.WirelessObservation{},
				},
				Errors: errors,
			}, fmt.Errorf("passive mode requested but not available: %w", err)
		}
	}

	// Perform platform-specific scanning
	observations := []*discover.WirelessObservation{}
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
	finalObservations := observations
	if finalObservations == nil {
		finalObservations = []*discover.WirelessObservation{}
	}

	report := &discover.DiscoverWapsReport{
		Config: &config,
		Result: &discover.DiscoverWapsResult{
			ScanMetadata: scanMetadata,
			Observations: finalObservations,
		},
		Errors: errors,
	}

	log.Info("Completed wireless access point discovery",
		svc1log.SafeParam("interface", interfaceName),
		svc1log.SafeParam("aps_found", len(observations)),
		svc1log.SafeParam("error_count", len(errors)),
		svc1log.SafeParam("duration_seconds", endTime.Sub(startTime).Seconds()))

	// Preserve partial observations in the report, but return the scan error so
	// callers do not treat a permission-limited or otherwise incomplete scan as
	// a successful result.
	return report, scanErr
}

// filterBySSID filters observations to only include those matching the target SSID.
func filterBySSID(observations []*discover.WirelessObservation, targetSSID string) []*discover.WirelessObservation {
	var filtered []*discover.WirelessObservation
	for _, obs := range observations {
		if obs.Ssid != nil && *obs.Ssid == targetSSID {
			filtered = append(filtered, obs)
		}
	}
	return filtered
}

// enrichWithVendorInfo adds vendor fingerprint information based on the BSSID OUI.
func enrichWithVendorInfo(obs *discover.WirelessObservation) {
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
//
// # TRUE PASSIVE SCANNING - LINUX ONLY
//
// Passive mode provides genuinely passive WiFi observation that emits NO RF signature.
// This is only possible on Linux with properly configured hardware and drivers.
//
// Requirements:
//   - Linux with compatible hardware (ath9k, ath5k, mt76 recommended)
//   - Interface configured in monitor mode with TX disabled
//   - Root privileges
//   - libpcap installed (libpcap-dev package)
//   - CGO enabled at build time
//
// Interface Setup (user must do this before scanning):
//
//	sudo systemctl stop NetworkManager  # or wpa_supplicant
//	sudo ip link set <iface> down
//	sudo iw dev <iface> set type monitor
//	sudo iw dev <iface> set monitor none
//	sudo ip link set <iface> up
//	sudo iw dev <iface> set power_save off
//
// Verification (recommended):
//
//	Use a second radio to capture and verify zero TX from your MAC.
func checkPassiveModeSupport(ctx context.Context, interfaceName string) error {
	log := svc1log.FromContext(ctx)

	switch runtime.GOOS {
	case "linux":
		// Linux is the only platform where true passive scanning is possible
		return checkPassiveModeLinux(ctx, interfaceName)

	case "darwin":
		// macOS: Apple controls the wireless stack; firmware TX is unavoidable
		log.Warn("Passive mode not available on macOS")
		return fmt.Errorf("passive mode on macOS is NOT POSSIBLE. " +
			"Apple's firmware always emits probe requests and other TX frames. " +
			"This is a hardware/firmware limitation, not a software one. " +
			"True passive scanning requires Linux with compatible hardware (ath9k, etc.)")

	case "windows":
		// Windows: Driver and OS constraints prevent true passivity
		log.Warn("Passive mode not available on Windows")
		return fmt.Errorf("passive mode on Windows is NOT POSSIBLE. " +
			"Windows drivers and the OS networking stack do not support TX suppression. " +
			"Even with Npcap and monitor mode, TX frames are unavoidable. " +
			"True passive scanning requires Linux with compatible hardware (ath9k, etc.)")

	default:
		return fmt.Errorf("passive mode is not supported on %s. "+
			"Only Linux supports true passive scanning", runtime.GOOS)
	}
}

// scanPassive performs true passive scanning using monitor mode packet capture.
//
// # TRUE PASSIVE SCANNING - ZERO RF EMISSION
//
// This function captures 802.11 beacon and probe response frames WITHOUT emitting
// any RF transmissions. This is achieved through:
//
//  1. Monitor mode with TX disabled (iw set monitor none)
//  2. Packet capture via libpcap (no TX path)
//  3. Passive channel hopping (iw set channel, no announcements)
//
// The user MUST configure the interface before calling:
//   - Interface in monitor mode
//   - TX suppression enabled
//   - Power save disabled
//   - NetworkManager/wpa_supplicant stopped
//
// Supported platforms: Linux only (with CGO and libpcap)
//
// Recommended hardware: ath9k, ath5k, mt76 chipsets
func scanPassive(ctx context.Context, interfaceName string, timeout int) ([]*discover.WirelessObservation, []int, error) {
	// Delegate to platform-specific implementation
	// Currently only Linux supports true passive scanning
	return scanPassiveLinux(ctx, interfaceName, timeout, nil)
}

// isRunningAsRoot checks if the current process has root/administrator privileges.
func isRunningAsRoot() bool { //nolint:unused
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
