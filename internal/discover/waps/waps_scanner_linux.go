//go:build linux

package waps

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Method-Security/infrascan/generated/go/common"
	"github.com/Method-Security/infrascan/generated/go/discover"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// scanLinux performs wireless scanning on Linux using iw, nmcli, or iwlist.
//
// Scan Strategy (privilege-aware):
//
// When running as ROOT (sudo):
//   - Priority: iw → nmcli → iwlist
//   - Rationale: 'iw' with root privileges can perform a fresh, comprehensive scan
//     and returns detailed technical data not available via nmcli:
//   - Channel width (20/40/80/160/320 MHz)
//   - WiFi generation / protocol capabilities (802.11n/ac/ax/be)
//   - HT/VHT/HE capability flags
//   - Detailed cipher suites (CCMP-256, GCMP-256, etc.)
//   - PMF/802.11w policy (MFPR/MFPC)
//   - Beacon interval and TSF timestamps
//
// When running as NON-ROOT (normal user):
//   - Priority: nmcli → iw → iwlist
//   - Rationale: Without root, 'iw' and 'iwlist' typically only return cached
//     results (often just the connected network). 'nmcli' queries NetworkManager's
//     scan cache which contains all recently seen networks.
//
// Fallback behavior: Each method is tried in priority order. The first method
// that succeeds and returns results is used. If all methods fail, an error is returned.
func scanLinux(ctx context.Context, interfaceName string, timeout int) ([]*discover.WirelessObservation, []int, error) {
	log := svc1log.FromContext(ctx)
	isRoot := isUnixRoot()
	log.Info("Starting Linux wireless scan",
		svc1log.SafeParam("running_as_root", isRoot))

	// Try to find a suitable interface if none specified
	if interfaceName == "" {
		var err error
		interfaceName, err = findWirelessInterface()
		if err != nil {
			return nil, nil, err
		}
	}

	var observations []*discover.WirelessObservation
	var channels []int
	var err error

	if isRoot {
		// Running as root: prefer iw for richer technical data
		observations, channels, err = scanAsRoot(ctx, log, interfaceName, timeout)
	} else {
		// Running as normal user: prefer nmcli for complete network list
		observations, channels, err = scanAsUser(ctx, log, interfaceName, timeout)
	}

	if err != nil {
		return nil, nil, err
	}

	return observations, channels, nil
}

// scanAsRoot implements the scan strategy for privileged (root) execution.
// Priority order: iw → nmcli → iwlist
// This order prioritizes iw because it provides the richest technical data when
// running with sufficient privileges to trigger a fresh scan.
func scanAsRoot(ctx context.Context, log svc1log.Logger, interfaceName string, timeout int) ([]*discover.WirelessObservation, []int, error) {
	// Try iw first (richest data with root privileges)
	observations, channels, err := scanWithIw(ctx, interfaceName, timeout)
	if err == nil && len(observations) > 0 {
		log.Info("Completed Linux wireless scan using iw (root mode)",
			svc1log.SafeParam("interface", interfaceName),
			svc1log.SafeParam("aps_found", len(observations)),
			svc1log.SafeParam("channels_scanned", len(channels)))
		return observations, channels, nil
	}
	if err != nil {
		log.Info("iw scan failed, trying nmcli", svc1log.SafeParam("error", err.Error()))
	}

	// Try nmcli next
	observations, channels, err = scanWithNmcli(ctx, interfaceName, timeout)
	if err == nil && len(observations) > 0 {
		log.Info("Completed Linux wireless scan using nmcli (root mode)",
			svc1log.SafeParam("interface", interfaceName),
			svc1log.SafeParam("aps_found", len(observations)),
			svc1log.SafeParam("channels_scanned", len(channels)))
		return observations, channels, nil
	}
	if err != nil {
		log.Info("nmcli scan failed, trying iwlist", svc1log.SafeParam("error", err.Error()))
	}

	// Fall back to iwlist
	observations, channels, err = scanWithIwlist(ctx, interfaceName, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("wireless scan failed (all methods exhausted): %w", err)
	}

	log.Info("Completed Linux wireless scan using iwlist (root mode)",
		svc1log.SafeParam("interface", interfaceName),
		svc1log.SafeParam("aps_found", len(observations)),
		svc1log.SafeParam("channels_scanned", len(channels)))

	return observations, channels, nil
}

// scanAsUser implements the scan strategy for unprivileged (non-root) execution.
// Priority order: nmcli → iw → iwlist
// This order prioritizes nmcli because iw/iwlist without root typically only
// return cached results (often just the currently connected network), while
// nmcli can access NetworkManager's complete scan cache.
func scanAsUser(ctx context.Context, log svc1log.Logger, interfaceName string, timeout int) ([]*discover.WirelessObservation, []int, error) {
	// Try nmcli first (most complete results without root)
	observations, channels, err := scanWithNmcli(ctx, interfaceName, timeout)
	if err == nil && len(observations) > 0 {
		log.Info("Completed Linux wireless scan using nmcli (user mode)",
			svc1log.SafeParam("interface", interfaceName),
			svc1log.SafeParam("aps_found", len(observations)),
			svc1log.SafeParam("channels_scanned", len(channels)))
		return observations, channels, nil
	}
	if err != nil {
		log.Info("nmcli scan failed or returned no results, trying iw", svc1log.SafeParam("error", err.Error()))
	}

	// Try iw next (may work on some systems)
	observations, channels, err = scanWithIw(ctx, interfaceName, timeout)
	if err == nil && len(observations) > 0 {
		log.Info("Completed Linux wireless scan using iw (user mode)",
			svc1log.SafeParam("interface", interfaceName),
			svc1log.SafeParam("aps_found", len(observations)),
			svc1log.SafeParam("channels_scanned", len(channels)))
		return observations, channels, nil
	}
	if err != nil {
		log.Info("iw scan failed, trying iwlist", svc1log.SafeParam("error", err.Error()))
	}

	// Fall back to iwlist
		observations, channels, err = scanWithIwlist(ctx, interfaceName, timeout)
		if err != nil {
		return nil, nil, fmt.Errorf("wireless scan failed (all methods exhausted): %w", err)
	}

	log.Info("Completed Linux wireless scan using iwlist (user mode)",
		svc1log.SafeParam("interface", interfaceName),
		svc1log.SafeParam("aps_found", len(observations)),
		svc1log.SafeParam("channels_scanned", len(channels)))

	return observations, channels, nil
}

// findWirelessInterface attempts to find an available wireless interface.
func findWirelessInterface() (string, error) {
	// Try to get wireless interfaces using iw
	cmd := exec.Command("iw", "dev")
	output, err := cmd.Output()
	if err == nil {
		// Parse output to find interface name
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "Interface ") {
				return strings.TrimPrefix(line, "Interface "), nil
			}
		}
	}

	// Fall back to iwconfig to find wireless interfaces
	cmd = exec.Command("iwconfig")
	output, err = cmd.Output()
	if err == nil {
		outputStr := string(output)
		lines := strings.Split(outputStr, "\n")
		var currentIface string
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			// Check if this line starts an interface entry (no leading whitespace)
			if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				parts := strings.Fields(trimmed)
				if len(parts) > 0 {
					currentIface = parts[0]
					// Check if this line or the next few lines contain "IEEE 802.11"
					// or "no wireless extensions"
					hasWireless := false
					hasNoWireless := false
					for j := i; j < len(lines) && j < i+10; j++ {
						checkLine := lines[j]
						if strings.Contains(checkLine, "IEEE 802.11") {
							hasWireless = true
							break
						}
						if strings.Contains(checkLine, "no wireless extensions") {
							hasNoWireless = true
							break
						}
						// Stop if we hit the next interface (line without leading whitespace)
						if j > i && !strings.HasPrefix(checkLine, " ") && !strings.HasPrefix(checkLine, "\t") {
							break
						}
					}
					if hasWireless && !hasNoWireless {
						return currentIface, nil
					}
				}
			}
		}
	}

	// Fall back to common interface names
	commonInterfaces := []string{"wlan0", "wlp2s0", "wlp3s0", "wlan1", "wlo1", "wlp4s0"}
	for _, iface := range commonInterfaces {
		// Check if interface exists
		cmd := exec.Command("ip", "link", "show", iface)
		if err := cmd.Run(); err == nil {
			return iface, nil
		}
	}

	return "", fmt.Errorf("no wireless interface found; please specify one with --interface")
}

// scanWithNmcli performs scanning using the nmcli command (NetworkManager).
// This is the most reliable method on modern Linux systems with NetworkManager.
// Uses --rescan yes to force a fresh point-in-time scan rather than returning cached results.
func scanWithNmcli(ctx context.Context, interfaceName string, timeout int) ([]*discover.WirelessObservation, []int, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// Use --rescan yes to force a fresh scan and wait for it to complete.
	// This ensures we get point-in-time results rather than accumulated cache.
	cmd := exec.CommandContext(timeoutCtx, "nmcli", "-t", "-f",
		"SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,MODE", "device", "wifi", "list", "--rescan", "yes")
	output, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("nmcli scan failed: %w", err)
	}

	return parseNmcliOutput(string(output))
}

// parseNmcliOutput parses the output of nmcli device wifi list.
func parseNmcliOutput(output string) ([]*discover.WirelessObservation, []int, error) {
	var observations []*discover.WirelessObservation
	channelMap := make(map[int]bool)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// nmcli -t output uses : as separator, but BSSID also contains colons
		// The BSSID colons are escaped as \: in -t mode
		// Format: SSID:BSSID:CHAN:FREQ:SIGNAL:SECURITY:MODE
		obs := parseNmcliLine(line)
		if obs != nil {
			observations = append(observations, obs)
			if obs.RadioCharacteristics != nil && obs.RadioCharacteristics.Channel != nil {
				channelMap[*obs.RadioCharacteristics.Channel] = true
			}
		}
	}

	var channels []int
	for ch := range channelMap {
		channels = append(channels, ch)
	}

	return observations, channels, nil
}

// parseNmcliLine parses a single line from nmcli -t output.
func parseNmcliLine(line string) *discover.WirelessObservation {
	// nmcli -t escapes colons in BSSID as \:
	// We need to split on unescaped colons only
	// Replace escaped colons temporarily
	placeholder := "\x00"
	line = strings.ReplaceAll(line, "\\:", placeholder)
	parts := strings.Split(line, ":")
	// Restore colons in each part
	for i := range parts {
		parts[i] = strings.ReplaceAll(parts[i], placeholder, ":")
	}

	// Expected format: SSID:BSSID:CHAN:FREQ:SIGNAL:SECURITY:MODE
	if len(parts) < 6 {
		return nil
	}

	ssid := parts[0]
	bssid := strings.ToUpper(parts[1])
	chanStr := parts[2]
	freqStr := parts[3]
	signalStr := parts[4]
	security := parts[5]

	obs := &discover.WirelessObservation{
		Bssid: bssid,
	}

	// Parse SSID
	if ssid != "" {
		obs.Ssid = &ssid
		obs.SsidLength = ptr(len(ssid))
		isHidden := false
		obs.IsHiddenSsid = &isHidden
	} else {
		isHidden := true
		obs.IsHiddenSsid = &isHidden
	}

	// Parse channel
	if channel, err := strconv.Atoi(chanStr); err == nil {
		freq := channelToFrequency(channel)
		band := determineFrequencyBand(channel)
		obs.RadioCharacteristics = &discover.RadioCharacteristics{
			Channel:      &channel,
			FrequencyMhz: &freq,
			Band:         band,
		}
	}

	// Parse frequency if channel parsing failed
	if obs.RadioCharacteristics == nil && freqStr != "" {
		// Format: "2462 MHz" or "5180 MHz"
		freqStr = strings.TrimSuffix(freqStr, " MHz")
		if freqMHz, err := strconv.Atoi(freqStr); err == nil {
			channel := frequencyToChannel(freqMHz)
			band := determineFrequencyBand(channel)
			obs.RadioCharacteristics = &discover.RadioCharacteristics{
				FrequencyMhz: &freqMHz,
				Channel:      &channel,
				Band:         band,
			}
		}
	}

	// Parse signal level (nmcli reports as percentage 0-100)
	if signal, err := strconv.Atoi(signalStr); err == nil {
		// Convert percentage to approximate dBm (rough approximation)
		// 100% ≈ -30 dBm, 0% ≈ -90 dBm
		rssi := -90 + (signal * 60 / 100)
		if obs.RadioCharacteristics == nil {
			obs.RadioCharacteristics = &discover.RadioCharacteristics{}
		}
		obs.RadioCharacteristics.Rssi = &rssi
	}

	// Parse security
	obs.SecurityConfiguration = parseNmcliSecurity(security)

	// Set observation metadata
	now := time.Now()
	passiveOnly := false
	beaconFrame := common.FrameTypeBeacon
	obs.ObservationMetadata = &discover.ObservationMetadata{
		Timestamp:   &now,
		PassiveOnly: &passiveOnly,
		FrameTypes:  []common.FrameType{beaconFrame},
	}

	return obs
}

// parseNmcliSecurity parses security information from nmcli output.
func parseNmcliSecurity(security string) *discover.SecurityConfiguration {
	config := &discover.SecurityConfiguration{}

	if security == "" || security == "--" {
		isOpen := true
		config.IsOpenNetwork = &isOpen
		enc := common.EncryptionProtocolNone
		config.EncryptionProtocol = &enc
		auth := common.AuthenticationMethodOpen
		config.AuthenticationMethod = &auth
		return config
	}

	isOpen := false
	config.IsOpenNetwork = &isOpen

	// Check for WPA3
	if strings.Contains(security, "WPA3") {
		version := common.WpaVersionWpa3
		config.WpaVersion = &version
		auth := common.AuthenticationMethodSae
		config.AuthenticationMethod = &auth
		keyMgmt := common.KeyManagementTypeSae
		config.KeyManagement = []common.KeyManagementType{keyMgmt}
		enc := common.EncryptionProtocolCcmp
		config.EncryptionProtocol = &enc
	} else if strings.Contains(security, "WPA2") {
		version := common.WpaVersionWpa2
		config.WpaVersion = &version
		auth := common.AuthenticationMethodPsk
		config.AuthenticationMethod = &auth
		keyMgmt := common.KeyManagementTypePsk
		config.KeyManagement = []common.KeyManagementType{keyMgmt}
		enc := common.EncryptionProtocolCcmp
		config.EncryptionProtocol = &enc
	} else if strings.Contains(security, "WPA1") || strings.Contains(security, "WPA ") {
		version := common.WpaVersionWpa1
		config.WpaVersion = &version
		auth := common.AuthenticationMethodPsk
		config.AuthenticationMethod = &auth
		keyMgmt := common.KeyManagementTypePsk
		config.KeyManagement = []common.KeyManagementType{keyMgmt}
		enc := common.EncryptionProtocolTkip
		config.EncryptionProtocol = &enc
	} else if strings.Contains(security, "WEP") {
		wepEnabled := true
		config.IsWepEnabled = &wepEnabled
		enc := common.EncryptionProtocolWep
		config.EncryptionProtocol = &enc
	}

	// Check for 802.1X/Enterprise
	if strings.Contains(security, "802.1X") || strings.Contains(security, "EAP") {
		auth := common.AuthenticationMethodEap
		config.AuthenticationMethod = &auth
		keyMgmt := common.KeyManagementTypeEap8021X
		config.KeyManagement = append(config.KeyManagement, keyMgmt)
	}

	return config
}

// scanWithIw performs scanning using the iw command.
func scanWithIw(ctx context.Context, interfaceName string, timeout int) ([]*discover.WirelessObservation, []int, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "iw", "dev", interfaceName, "scan")
	output, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("iw scan failed: %w", err)
	}

	return parseIwOutput(string(output))
}

// scanWithIwlist performs scanning using the iwlist command.
func scanWithIwlist(ctx context.Context, interfaceName string, timeout int) ([]*discover.WirelessObservation, []int, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "iwlist", interfaceName, "scan")
	output, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("iwlist scan failed: %w", err)
	}

	return parseIwlistOutput(string(output))
}

// parseIwOutput parses the output of iw dev <interface> scan.
func parseIwOutput(output string) ([]*discover.WirelessObservation, []int, error) {
	var observations []*discover.WirelessObservation
	channelMap := make(map[int]bool)

	// Split output by BSS entries
	bssRegex := regexp.MustCompile(`(?m)^BSS ([0-9a-fA-F:]+)`)
	matches := bssRegex.FindAllStringSubmatchIndex(output, -1)

	for i, match := range matches {
		bssid := strings.ToUpper(output[match[2]:match[3]])

		// Get the section for this BSS
		start := match[0]
		end := len(output)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		section := output[start:end]

		obs := parseIwBssSection(bssid, section)
		if obs != nil {
			observations = append(observations, obs)
			if obs.RadioCharacteristics != nil && obs.RadioCharacteristics.Channel != nil {
				channelMap[*obs.RadioCharacteristics.Channel] = true
			}
		}
	}

	var channels []int
	for ch := range channelMap {
		channels = append(channels, ch)
	}

	return observations, channels, nil
}

// parseIwBssSection parses a single BSS section from iw output.
func parseIwBssSection(bssid, section string) *discover.WirelessObservation {
	obs := &discover.WirelessObservation{
		Bssid: bssid,
	}

	// Parse SSID
	ssidRegex := regexp.MustCompile(`SSID: (.*)`)
	if match := ssidRegex.FindStringSubmatch(section); len(match) > 1 {
		ssid := match[1]
		if ssid != "" {
			obs.Ssid = &ssid
			obs.SsidLength = ptr(len(ssid))
			isHidden := false
			obs.IsHiddenSsid = &isHidden
		} else {
			isHidden := true
			obs.IsHiddenSsid = &isHidden
		}
	}

	// Parse frequency and channel
	freqRegex := regexp.MustCompile(`freq: (\d+)`)
	if match := freqRegex.FindStringSubmatch(section); len(match) > 1 {
		freq, _ := strconv.Atoi(match[1])
		channel := frequencyToChannel(freq)
		band := determineFrequencyBand(channel)

		obs.RadioCharacteristics = &discover.RadioCharacteristics{
			FrequencyMhz: &freq,
			Channel:      &channel,
			Band:         band,
		}
	}

	// Parse signal level
	signalRegex := regexp.MustCompile(`signal: (-?\d+)`)
	if match := signalRegex.FindStringSubmatch(section); len(match) > 1 {
		rssi, _ := strconv.Atoi(match[1])
		if obs.RadioCharacteristics == nil {
			obs.RadioCharacteristics = &discover.RadioCharacteristics{}
		}
		obs.RadioCharacteristics.Rssi = &rssi
	}

	// Parse security from RSN/WPA IEs
	obs.SecurityConfiguration = parseIwSecurity(section)

	// Parse HT/VHT/HE capabilities
	obs.ProtocolCapabilities = parseIwCapabilities(section)

	// Parse channel width
	if obs.RadioCharacteristics != nil {
		obs.RadioCharacteristics.ChannelWidth = parseIwChannelWidth(section)
	}

	// Set observation metadata
	now := time.Now()
	passiveOnly := false
	beaconFrame := common.FrameTypeBeacon
	obs.ObservationMetadata = &discover.ObservationMetadata{
		Timestamp:   &now,
		PassiveOnly: &passiveOnly,
		FrameTypes:  []common.FrameType{beaconFrame},
	}

	return obs
}

// parseIwSecurity parses security information from iw output.
func parseIwSecurity(section string) *discover.SecurityConfiguration {
	config := &discover.SecurityConfiguration{}

	// Check for RSN (WPA2/WPA3)
	hasRSN := strings.Contains(section, "RSN:")
	hasWPA := strings.Contains(section, "WPA:")

	if !hasRSN && !hasWPA {
		// Check for WEP
		if strings.Contains(section, "WEP") {
			wepEnabled := true
			config.IsWepEnabled = &wepEnabled
			enc := common.EncryptionProtocolWep
			config.EncryptionProtocol = &enc
		} else {
			isOpen := true
			config.IsOpenNetwork = &isOpen
			enc := common.EncryptionProtocolNone
			config.EncryptionProtocol = &enc
			auth := common.AuthenticationMethodOpen
			config.AuthenticationMethod = &auth
		}
		return config
	}

	isOpen := false
	config.IsOpenNetwork = &isOpen

	// Parse WPA version
	if hasRSN {
		if strings.Contains(section, "SAE") {
			version := common.WpaVersionWpa3
			config.WpaVersion = &version
			auth := common.AuthenticationMethodSae
			config.AuthenticationMethod = &auth
			keyMgmt := common.KeyManagementTypeSae
			config.KeyManagement = []common.KeyManagementType{keyMgmt}
		} else {
			version := common.WpaVersionWpa2
			config.WpaVersion = &version
		}
	} else if hasWPA {
		version := common.WpaVersionWpa1
		config.WpaVersion = &version
	}

	// Parse key management
	if strings.Contains(section, "PSK") && config.KeyManagement == nil {
		keyMgmt := common.KeyManagementTypePsk
		config.KeyManagement = []common.KeyManagementType{keyMgmt}
		// Set PSK auth method if not already set (e.g., for WPA/WPA2 Personal)
		if config.AuthenticationMethod == nil {
			auth := common.AuthenticationMethodPsk
			config.AuthenticationMethod = &auth
		}
	}
	if strings.Contains(section, "802.1X") || strings.Contains(section, "EAP") {
		auth := common.AuthenticationMethodEap
		config.AuthenticationMethod = &auth
		keyMgmt := common.KeyManagementTypeEap8021X
		config.KeyManagement = append(config.KeyManagement, keyMgmt)
	}

	// Parse cipher suites
	if strings.Contains(section, "CCMP-256") {
		enc := common.EncryptionProtocolCcmp256
		config.EncryptionProtocol = &enc
		cipher := common.CipherSuiteCcmp256
		config.PairwiseCipherSuites = []common.CipherSuite{cipher}
	} else if strings.Contains(section, "GCMP-256") {
		enc := common.EncryptionProtocolGcmp256
		config.EncryptionProtocol = &enc
		cipher := common.CipherSuiteGcmp256
		config.PairwiseCipherSuites = []common.CipherSuite{cipher}
	} else if strings.Contains(section, "CCMP") {
		enc := common.EncryptionProtocolCcmp
		config.EncryptionProtocol = &enc
		cipher := common.CipherSuiteCcmp128
		config.PairwiseCipherSuites = []common.CipherSuite{cipher}
	} else if strings.Contains(section, "TKIP") {
		enc := common.EncryptionProtocolTkip
		config.EncryptionProtocol = &enc
		cipher := common.CipherSuiteTkip
		config.PairwiseCipherSuites = []common.CipherSuite{cipher}
	}

	// Parse PMF (802.11w)
	if strings.Contains(section, "MFPR") {
		pmf := common.PmfPolicyRequired
		config.PmfPolicy = &pmf
	} else if strings.Contains(section, "MFPC") {
		pmf := common.PmfPolicyOptional
		config.PmfPolicy = &pmf
	}

	return config
}

// parseIwCapabilities parses protocol capabilities from iw output.
func parseIwCapabilities(section string) *discover.ProtocolCapabilities {
	caps := &discover.ProtocolCapabilities{}

	// Check for HT (802.11n)
	if strings.Contains(section, "HT capabilities") || strings.Contains(section, "HT20") || strings.Contains(section, "HT40") {
		supports := true
		caps.Supports80211N = &supports
	}

	// Check for VHT (802.11ac)
	if strings.Contains(section, "VHT capabilities") {
		supports := true
		caps.Supports80211Ac = &supports
		gen := common.WifiGenerationWifi5
		caps.WifiGeneration = &gen
	}

	// Check for HE (802.11ax)
	if strings.Contains(section, "HE capabilities") || strings.Contains(section, "HE Phy Capabilities") {
		supports := true
		caps.Supports80211Ax = &supports
		gen := common.WifiGenerationWifi6
		caps.WifiGeneration = &gen
	}

	// Check for EHT (802.11be)
	if strings.Contains(section, "EHT capabilities") {
		supports := true
		caps.Supports80211Be = &supports
		gen := common.WifiGenerationWifi7
		caps.WifiGeneration = &gen
	}

	// Default to WiFi 4 if only HT is present
	if caps.WifiGeneration == nil && caps.Supports80211N != nil && *caps.Supports80211N {
		gen := common.WifiGenerationWifi4
		caps.WifiGeneration = &gen
	}

	return caps
}

// parseIwChannelWidth parses channel width from iw output.
func parseIwChannelWidth(section string) *common.ChannelWidth {
	var width common.ChannelWidth

	if strings.Contains(section, "320 MHz") {
		width = common.ChannelWidthWidth320Mhz
	} else if strings.Contains(section, "160 MHz") || strings.Contains(section, "160MHz") {
		width = common.ChannelWidthWidth160Mhz
	} else if strings.Contains(section, "80 MHz") || strings.Contains(section, "80MHz") {
		width = common.ChannelWidthWidth80Mhz
	} else if strings.Contains(section, "40 MHz") || strings.Contains(section, "HT40") {
		width = common.ChannelWidthWidth40Mhz
	} else {
		width = common.ChannelWidthWidth20Mhz
	}

	return &width
}

// parseIwlistOutput parses the output of iwlist scan.
func parseIwlistOutput(output string) ([]*discover.WirelessObservation, []int, error) {
	var observations []*discover.WirelessObservation
	channelMap := make(map[int]bool)

	// Split by Cell entries
	cellRegex := regexp.MustCompile(`(?m)Cell \d+ - Address: ([0-9A-Fa-f:]+)`)
	matches := cellRegex.FindAllStringSubmatchIndex(output, -1)

	for i, match := range matches {
		bssid := strings.ToUpper(output[match[2]:match[3]])

		start := match[0]
		end := len(output)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		section := output[start:end]

		obs := parseIwlistCell(bssid, section)
		if obs != nil {
			observations = append(observations, obs)
			if obs.RadioCharacteristics != nil && obs.RadioCharacteristics.Channel != nil {
				channelMap[*obs.RadioCharacteristics.Channel] = true
			}
		}
	}

	var channels []int
	for ch := range channelMap {
		channels = append(channels, ch)
	}

	return observations, channels, nil
}

// parseIwlistCell parses a single Cell from iwlist output.
func parseIwlistCell(bssid, section string) *discover.WirelessObservation {
	obs := &discover.WirelessObservation{
		Bssid: bssid,
	}

	// Parse ESSID
	essidRegex := regexp.MustCompile(`ESSID:"(.*)"`)
	if match := essidRegex.FindStringSubmatch(section); len(match) > 1 {
		ssid := match[1]
		if ssid != "" {
			obs.Ssid = &ssid
			obs.SsidLength = ptr(len(ssid))
			isHidden := false
			obs.IsHiddenSsid = &isHidden
		} else {
			isHidden := true
			obs.IsHiddenSsid = &isHidden
		}
	}

	// Parse channel
	channelRegex := regexp.MustCompile(`Channel:(\d+)`)
	if match := channelRegex.FindStringSubmatch(section); len(match) > 1 {
		channel, _ := strconv.Atoi(match[1])
		freq := channelToFrequency(channel)
		band := determineFrequencyBand(channel)

		obs.RadioCharacteristics = &discover.RadioCharacteristics{
			Channel:      &channel,
			FrequencyMhz: &freq,
			Band:         band,
		}
	}

	// Parse frequency if channel not found
	if obs.RadioCharacteristics == nil {
		freqRegex := regexp.MustCompile(`Frequency:(\d+\.?\d*) GHz`)
		if match := freqRegex.FindStringSubmatch(section); len(match) > 1 {
			freqGHz, _ := strconv.ParseFloat(match[1], 64)
			freqMHz := int(freqGHz * 1000)
			channel := frequencyToChannel(freqMHz)
			band := determineFrequencyBand(channel)

			obs.RadioCharacteristics = &discover.RadioCharacteristics{
				FrequencyMhz: &freqMHz,
				Channel:      &channel,
				Band:         band,
			}
		}
	}

	// Parse signal level
	signalRegex := regexp.MustCompile(`Signal level[=:](-?\d+)`)
	if match := signalRegex.FindStringSubmatch(section); len(match) > 1 {
		rssi, _ := strconv.Atoi(match[1])
		if obs.RadioCharacteristics == nil {
			obs.RadioCharacteristics = &discover.RadioCharacteristics{}
		}
		obs.RadioCharacteristics.Rssi = &rssi
	}

	// Parse encryption
	obs.SecurityConfiguration = parseIwlistSecurity(section)

	// Set observation metadata
	now := time.Now()
	passiveOnly := false
	beaconFrame := common.FrameTypeBeacon
	obs.ObservationMetadata = &discover.ObservationMetadata{
		Timestamp:   &now,
		PassiveOnly: &passiveOnly,
		FrameTypes:  []common.FrameType{beaconFrame},
	}

	return obs
}

// parseIwlistSecurity parses security from iwlist output.
func parseIwlistSecurity(section string) *discover.SecurityConfiguration {
	config := &discover.SecurityConfiguration{}

	// Check encryption status
	if strings.Contains(section, "Encryption key:off") {
		isOpen := true
		config.IsOpenNetwork = &isOpen
		enc := common.EncryptionProtocolNone
		config.EncryptionProtocol = &enc
		auth := common.AuthenticationMethodOpen
		config.AuthenticationMethod = &auth
		return config
	}

	isOpen := false
	config.IsOpenNetwork = &isOpen

	// Check for WPA2/WPA
	if strings.Contains(section, "WPA2") {
		version := common.WpaVersionWpa2
		config.WpaVersion = &version
	} else if strings.Contains(section, "WPA") {
		version := common.WpaVersionWpa1
		config.WpaVersion = &version
	}

	// Check for PSK/EAP
	if strings.Contains(section, "PSK") {
		keyMgmt := common.KeyManagementTypePsk
		config.KeyManagement = []common.KeyManagementType{keyMgmt}
		auth := common.AuthenticationMethodPsk
		config.AuthenticationMethod = &auth
	}
	if strings.Contains(section, "802.1x") || strings.Contains(section, "EAP") {
		keyMgmt := common.KeyManagementTypeEap8021X
		config.KeyManagement = append(config.KeyManagement, keyMgmt)
		auth := common.AuthenticationMethodEap
		config.AuthenticationMethod = &auth
	}

	// Check cipher
	if strings.Contains(section, "CCMP") {
		enc := common.EncryptionProtocolCcmp
		config.EncryptionProtocol = &enc
		cipher := common.CipherSuiteCcmp128
		config.PairwiseCipherSuites = []common.CipherSuite{cipher}
	} else if strings.Contains(section, "TKIP") {
		enc := common.EncryptionProtocolTkip
		config.EncryptionProtocol = &enc
		cipher := common.CipherSuiteTkip
		config.PairwiseCipherSuites = []common.CipherSuite{cipher}
	}

	return config
}

// frequencyToChannel converts a frequency in MHz to a WiFi channel number.
func frequencyToChannel(freqMHz int) int {
	// 2.4 GHz band
	if freqMHz >= 2412 && freqMHz <= 2484 {
		if freqMHz == 2484 {
			return 14
		}
		return (freqMHz - 2407) / 5
	}

	// 5 GHz band
	if freqMHz >= 5170 && freqMHz <= 5825 {
		return (freqMHz - 5000) / 5
	}

	// 6 GHz band
	if freqMHz >= 5955 && freqMHz <= 7115 {
		return (freqMHz - 5950) / 5
	}

	return 0
}
