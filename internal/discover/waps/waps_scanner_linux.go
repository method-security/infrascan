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

// scanLinux performs wireless scanning on Linux using iw or iwlist.
// Note: This requires appropriate permissions (typically root).
func scanLinux(ctx context.Context, interfaceName string, timeout int) ([]*discover.PassiveWirelessObservation, []int, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Linux wireless scan")

	// Try to find a suitable interface if none specified
	if interfaceName == "" {
		var err error
		interfaceName, err = findWirelessInterface()
		if err != nil {
			return nil, nil, err
		}
	}

	// Try iw first, fall back to iwlist
	observations, channels, err := scanWithIw(ctx, interfaceName, timeout)
	if err != nil {
		log.Info("iw scan failed, trying iwlist", svc1log.SafeParam("error", err.Error()))
		observations, channels, err = scanWithIwlist(ctx, interfaceName, timeout)
		if err != nil {
			return nil, nil, fmt.Errorf("wireless scan failed: %w", err)
		}
	}

	log.Info("Completed Linux wireless scan",
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

	// Fall back to common interface names
	commonInterfaces := []string{"wlan0", "wlp2s0", "wlp3s0", "wlan1"}
	for _, iface := range commonInterfaces {
		// Check if interface exists
		cmd := exec.Command("ip", "link", "show", iface)
		if err := cmd.Run(); err == nil {
			return iface, nil
		}
	}

	return "", fmt.Errorf("no wireless interface found; please specify one with --interface")
}

// scanWithIw performs scanning using the iw command.
func scanWithIw(ctx context.Context, interfaceName string, timeout int) ([]*discover.PassiveWirelessObservation, []int, error) {
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
func scanWithIwlist(ctx context.Context, interfaceName string, timeout int) ([]*discover.PassiveWirelessObservation, []int, error) {
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
func parseIwOutput(output string) ([]*discover.PassiveWirelessObservation, []int, error) {
	var observations []*discover.PassiveWirelessObservation
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
func parseIwBssSection(bssid, section string) *discover.PassiveWirelessObservation {
	obs := &discover.PassiveWirelessObservation{
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
func parseIwlistOutput(output string) ([]*discover.PassiveWirelessObservation, []int, error) {
	var observations []*discover.PassiveWirelessObservation
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
func parseIwlistCell(bssid, section string) *discover.PassiveWirelessObservation {
	obs := &discover.PassiveWirelessObservation{
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
