//go:build windows

package waps

import (
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

// scanWindows performs wireless scanning on Windows using netsh wlan.
func scanWindows(ctx context.Context, interfaceName string, timeout int) ([]*discover.WirelessObservation, []int, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Windows wireless scan using netsh wlan")

	// Create command with timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// Build command - mode=bssid gives us detailed info including all BSSIDs
	args := []string{"wlan", "show", "networks", "mode=bssid"}
	if interfaceName != "" {
		args = append(args, "interface="+interfaceName)
	}

	cmd := exec.CommandContext(timeoutCtx, "netsh", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("netsh wlan scan failed: %w", err)
	}

	observations, channelsScanned := parseNetshOutput(string(output))

	log.Info("Completed Windows wireless scan",
		svc1log.SafeParam("aps_found", len(observations)),
		svc1log.SafeParam("channels_scanned", len(channelsScanned)))

	return observations, channelsScanned, nil
}

// parseNetshOutput parses the output of netsh wlan show networks mode=bssid.
// Output format:
//
//	SSID 1 : NetworkName
//	    Network type            : Infrastructure
//	    Authentication          : WPA2-Personal
//	    Encryption              : CCMP
//	    BSSID 1                 : aa:bb:cc:dd:ee:ff
//	         Signal             : 85%
//	         Radio type         : 802.11ac
//	         Channel            : 36
func parseNetshOutput(output string) ([]*discover.WirelessObservation, []int) {
	var observations []*discover.WirelessObservation
	channelMap := make(map[int]bool)

	// Split into network blocks
	lines := strings.Split(output, "\n")

	var currentSSID string
	var currentNetworkType string
	var currentAuth string
	var currentEncryption string
	var currentBSSID string
	var currentSignal int
	var currentRadioType string
	var currentChannel int

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse SSID
		if strings.HasPrefix(line, "SSID") && strings.Contains(line, ":") {
			// Save previous BSSID observation if exists
			if currentBSSID != "" {
				obs := buildWindowsObservation(currentSSID, currentBSSID, currentAuth, currentEncryption,
					currentSignal, currentRadioType, currentChannel)
				if obs != nil {
					observations = append(observations, obs)
					if currentChannel > 0 {
						channelMap[currentChannel] = true
					}
				}
			}

			// Reset for new network
			currentBSSID = ""
			currentSignal = 0
			currentRadioType = ""
			currentChannel = 0

			// Extract SSID (handle "SSID 1 : name" format)
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentSSID = strings.TrimSpace(parts[1])
			}
			continue
		}

		// Parse network type
		if strings.HasPrefix(line, "Network type") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentNetworkType = strings.TrimSpace(parts[1])
			}
			continue
		}

		// Parse authentication
		if strings.HasPrefix(line, "Authentication") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentAuth = strings.TrimSpace(parts[1])
			}
			continue
		}

		// Parse encryption
		if strings.HasPrefix(line, "Encryption") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentEncryption = strings.TrimSpace(parts[1])
			}
			continue
		}

		// Parse BSSID
		if strings.HasPrefix(line, "BSSID") && strings.Contains(line, ":") {
			// Save previous BSSID observation if exists (multiple BSSIDs per SSID)
			if currentBSSID != "" {
				obs := buildWindowsObservation(currentSSID, currentBSSID, currentAuth, currentEncryption,
					currentSignal, currentRadioType, currentChannel)
				if obs != nil {
					observations = append(observations, obs)
					if currentChannel > 0 {
						channelMap[currentChannel] = true
					}
				}
			}

			// Extract BSSID (handle "BSSID 1 : aa:bb:cc:dd:ee:ff" format)
			bssidRegex := regexp.MustCompile(`([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}`)
			if match := bssidRegex.FindString(line); match != "" {
				currentBSSID = strings.ToUpper(strings.ReplaceAll(match, "-", ":"))
			}
			// Reset per-BSSID fields
			currentSignal = 0
			currentRadioType = ""
			currentChannel = 0
			continue
		}

		// Parse signal strength
		if strings.HasPrefix(line, "Signal") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				signalStr := strings.TrimSpace(parts[1])
				signalStr = strings.TrimSuffix(signalStr, "%")
				if sig, err := strconv.Atoi(signalStr); err == nil {
					// Convert percentage to approximate dBm (rough estimate)
					// 100% ≈ -30 dBm, 0% ≈ -100 dBm
					currentSignal = -100 + (sig * 70 / 100)
				}
			}
			continue
		}

		// Parse radio type
		if strings.HasPrefix(line, "Radio type") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentRadioType = strings.TrimSpace(parts[1])
			}
			continue
		}

		// Parse channel
		if strings.HasPrefix(line, "Channel") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if ch, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					currentChannel = ch
				}
			}
			continue
		}
	}

	// Don't forget the last BSSID
	if currentBSSID != "" {
		obs := buildWindowsObservation(currentSSID, currentBSSID, currentAuth, currentEncryption,
			currentSignal, currentRadioType, currentChannel)
		if obs != nil {
			observations = append(observations, obs)
			if currentChannel > 0 {
				channelMap[currentChannel] = true
			}
		}
	}

	// Ignore currentNetworkType for now but could use it
	_ = currentNetworkType

	var channels []int
	for ch := range channelMap {
		channels = append(channels, ch)
	}

	return observations, channels
}

// buildWindowsObservation creates an observation from parsed Windows data.
func buildWindowsObservation(ssid, bssid, auth, encryption string, signal int, radioType string, channel int) *discover.WirelessObservation {
	if bssid == "" {
		return nil
	}

	obs := &discover.WirelessObservation{
		Bssid: bssid,
	}

	// Set SSID
	if ssid != "" {
		obs.Ssid = &ssid
		obs.SsidLength = ptr(len(ssid))
		isHidden := false
		obs.IsHiddenSsid = &isHidden
	} else {
		isHidden := true
		obs.IsHiddenSsid = &isHidden
	}

	// Set radio characteristics
	if channel > 0 || signal != 0 {
		band := determineFrequencyBand(channel)
		freq := channelToFrequency(channel)

		obs.RadioCharacteristics = &discover.RadioCharacteristics{
			Channel:      &channel,
			FrequencyMhz: &freq,
			Band:         band,
			Rssi:         &signal,
		}
	}

	// Parse security configuration
	obs.SecurityConfiguration = parseWindowsSecurity(auth, encryption)

	// Parse WiFi generation from radio type
	obs.ProtocolCapabilities = parseWindowsRadioType(radioType)

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

// parseWindowsSecurity parses security info from Windows netsh output.
func parseWindowsSecurity(auth, encryption string) *discover.SecurityConfiguration {
	config := &discover.SecurityConfiguration{}

	// Check for open network
	if auth == "Open" && encryption == "None" {
		isOpen := true
		config.IsOpenNetwork = &isOpen
		enc := common.EncryptionProtocolNone
		config.EncryptionProtocol = &enc
		authMethod := common.AuthenticationMethodOpen
		config.AuthenticationMethod = &authMethod
		return config
	}

	isOpen := false
	config.IsOpenNetwork = &isOpen

	// Parse authentication
	switch {
	case strings.Contains(auth, "WPA3"):
		version := common.WpaVersionWpa3
		config.WpaVersion = &version
		if strings.Contains(auth, "Personal") {
			authMethod := common.AuthenticationMethodSae
			config.AuthenticationMethod = &authMethod
			keyMgmt := common.KeyManagementTypeSae
			config.KeyManagement = []common.KeyManagementType{keyMgmt}
		} else if strings.Contains(auth, "Enterprise") {
			authMethod := common.AuthenticationMethodEap
			config.AuthenticationMethod = &authMethod
			keyMgmt := common.KeyManagementTypeEap8021X
			config.KeyManagement = []common.KeyManagementType{keyMgmt}
		}
	case strings.Contains(auth, "WPA2"):
		version := common.WpaVersionWpa2
		config.WpaVersion = &version
		if strings.Contains(auth, "Personal") {
			keyMgmt := common.KeyManagementTypePsk
			config.KeyManagement = []common.KeyManagementType{keyMgmt}
		} else if strings.Contains(auth, "Enterprise") {
			authMethod := common.AuthenticationMethodEap
			config.AuthenticationMethod = &authMethod
			keyMgmt := common.KeyManagementTypeEap8021X
			config.KeyManagement = []common.KeyManagementType{keyMgmt}
		}
	case strings.Contains(auth, "WPA"):
		version := common.WpaVersionWpa1
		config.WpaVersion = &version
		if strings.Contains(auth, "Personal") {
			keyMgmt := common.KeyManagementTypePsk
			config.KeyManagement = []common.KeyManagementType{keyMgmt}
		}
	case strings.Contains(auth, "WEP"):
		wepEnabled := true
		config.IsWepEnabled = &wepEnabled
		enc := common.EncryptionProtocolWep
		config.EncryptionProtocol = &enc
	}

	// Parse encryption
	switch encryption {
	case "CCMP":
		enc := common.EncryptionProtocolCcmp
		config.EncryptionProtocol = &enc
		cipher := common.CipherSuiteCcmp128
		config.PairwiseCipherSuites = []common.CipherSuite{cipher}
	case "GCMP":
		enc := common.EncryptionProtocolGcmp
		config.EncryptionProtocol = &enc
		cipher := common.CipherSuiteGcmp128
		config.PairwiseCipherSuites = []common.CipherSuite{cipher}
	case "TKIP":
		enc := common.EncryptionProtocolTkip
		config.EncryptionProtocol = &enc
		cipher := common.CipherSuiteTkip
		config.PairwiseCipherSuites = []common.CipherSuite{cipher}
	}

	return config
}

// parseWindowsRadioType parses WiFi generation from Windows radio type string.
func parseWindowsRadioType(radioType string) *discover.ProtocolCapabilities {
	caps := &discover.ProtocolCapabilities{}

	switch {
	case strings.Contains(radioType, "802.11be"):
		gen := common.WifiGenerationWifi7
		caps.WifiGeneration = &gen
		supports := true
		caps.Supports80211Be = &supports
		caps.Supports80211Ax = &supports
		caps.Supports80211Ac = &supports
		caps.Supports80211N = &supports
	case strings.Contains(radioType, "802.11ax"):
		gen := common.WifiGenerationWifi6
		caps.WifiGeneration = &gen
		supports := true
		caps.Supports80211Ax = &supports
		caps.Supports80211Ac = &supports
		caps.Supports80211N = &supports
	case strings.Contains(radioType, "802.11ac"):
		gen := common.WifiGenerationWifi5
		caps.WifiGeneration = &gen
		supports := true
		caps.Supports80211Ac = &supports
		caps.Supports80211N = &supports
	case strings.Contains(radioType, "802.11n"):
		gen := common.WifiGenerationWifi4
		caps.WifiGeneration = &gen
		supports := true
		caps.Supports80211N = &supports
	case strings.Contains(radioType, "802.11g"), strings.Contains(radioType, "802.11b"), strings.Contains(radioType, "802.11a"):
		gen := common.WifiGenerationLegacy
		caps.WifiGeneration = &gen
	default:
		gen := common.WifiGenerationUnknown
		caps.WifiGeneration = &gen
	}

	return caps
}
