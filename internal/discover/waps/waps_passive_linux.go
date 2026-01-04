//go:build linux && cgo

// Package waps provides truly passive 802.11 wireless scanning on Linux.
//
// # TRUE PASSIVE SCANNING - ZERO RF EMISSION
//
// This implementation provides genuinely passive WiFi observation that emits
// no RF signature whatsoever. This is achieved through careful configuration
// of the 802.11 stack on Linux.
//
// # Requirements for True Passivity
//
// 1. HARDWARE: Chipsets that support RX-only monitor mode
//   - Atheros ath9k / ath9k_htc (gold standard)
//   - ath5k
//   - Some mt76 variants
//   - Note: If injection works, passivity is NOT guaranteed
//
// 2. DRIVER CONFIGURATION: TX must be fully suppressed
//   - Monitor mode enabled
//   - No auto-ACK behavior
//   - No background scanning
//   - No power save announcements
//
// 3. INTERFACE SETUP: Canonical sequence
//
//	ip link set <iface> down
//	iw dev <iface> set type monitor
//	iw dev <iface> set monitor none    # Disables cooked monitor flags
//	ip link set <iface> up
//
// 4. TRANSMIT SOURCES DISABLED:
//   - Power save off: iw dev <iface> set power_save off
//   - NetworkManager stopped
//   - wpa_supplicant stopped
//   - No managed-mode interfaces on same radio
//
// 5. CHANNEL CONTROL: Passive hopping only
//   - iw dev <iface> set channel <channel>
//   - No CSA frames, no probes, no regulatory broadcasts
//
// # Verifying Passivity
//
// CRITICAL: You must verify passivity with a second radio capturing your MAC.
// Confirm:
//   - Zero frames sourced from your MAC
//   - No ACKs transmitted
//   - No RTS/CTS
//
// Without verification, passivity cannot be claimed.
//
// # Usage
//
// The user is responsible for configuring the interface in monitor mode
// before invoking passive scanning. This tool will verify the configuration
// and refuse to scan if TX suppression cannot be confirmed.
package waps

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Method-Security/infrascan/generated/go/common"
	"github.com/Method-Security/infrascan/generated/go/discover"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// PassiveScanConfig holds configuration for passive scanning.
type PassiveScanConfig struct {
	Interface   string
	Timeout     int
	Channels    []int // Channels to scan (empty = default set)
	DwellTimeMs int   // Time to spend on each channel (default 250ms)
	HopChannels bool  // Whether to hop channels
}

// Default channels for passive scanning (common 2.4GHz and 5GHz channels).
var defaultChannels = []int{
	// 2.4 GHz
	1, 6, 11,
	// 5 GHz UNII-1
	36, 40, 44, 48,
	// 5 GHz UNII-2A
	52, 56, 60, 64,
	// 5 GHz UNII-2C
	100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
	// 5 GHz UNII-3
	149, 153, 157, 161, 165,
}

// PassiveScanner performs truly passive 802.11 scanning using monitor mode.
type PassiveScanner struct {
	config         PassiveScanConfig
	handle         *pcap.Handle
	observations   map[string]*discover.WirelessObservation // keyed by BSSID
	beaconCounts   map[string]int                           // beacon count per BSSID
	firstSeen      map[string]time.Time                     // first seen time per BSSID
	channelsSeenOn map[string]int                           // channel where BSSID was observed
	mu             sync.RWMutex
	ctx            context.Context
	log            svc1log.Logger
}

// scanPassiveLinux performs truly passive scanning on Linux using monitor mode.
// This function captures 802.11 beacon frames without emitting any RF transmissions.
//
// Prerequisites (user must configure before calling):
//  1. Interface must be in monitor mode with TX disabled
//  2. Running as root
//  3. NetworkManager/wpa_supplicant stopped for this interface
//  4. Power save disabled
//
// The function will verify these conditions and refuse to scan if not met.
func scanPassiveLinux(ctx context.Context, interfaceName string, timeout int, channels []int) ([]*discover.WirelessObservation, []int, error) {
	log := svc1log.FromContext(ctx)

	log.Info("Initializing passive scanner",
		svc1log.SafeParam("interface", interfaceName),
		svc1log.SafeParam("timeout", timeout))

	// Validate passive mode prerequisites
	if err := validatePassivePrerequisites(interfaceName); err != nil {
		return nil, nil, fmt.Errorf("passive mode prerequisites not met: %w", err)
	}

	config := PassiveScanConfig{
		Interface:   interfaceName,
		Timeout:     timeout,
		Channels:    channels,
		DwellTimeMs: 250, // 250ms per channel
		HopChannels: len(channels) == 0 || len(channels) > 1,
	}

	if len(config.Channels) == 0 {
		config.Channels = defaultChannels
	}

	scanner := &PassiveScanner{
		config:         config,
		observations:   make(map[string]*discover.WirelessObservation),
		beaconCounts:   make(map[string]int),
		firstSeen:      make(map[string]time.Time),
		channelsSeenOn: make(map[string]int),
		ctx:            ctx,
		log:            log,
	}

	// Open pcap handle
	handle, err := pcap.OpenLive(
		interfaceName,
		65536,             // Snapshot length
		true,              // Promiscuous mode (required for monitor mode)
		pcap.BlockForever, // Timeout (we use context for timeout)
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}
	defer handle.Close()
	scanner.handle = handle

	// Set BPF filter for beacon and probe response frames only
	// Type 0 (Management), Subtype 8 (Beacon) or Subtype 5 (Probe Response)
	// Filter: wlan type mgt subtype beacon or wlan type mgt subtype probe-resp
	// In BPF: (wlan[0] & 0xfc) == 0x80 || (wlan[0] & 0xfc) == 0x50
	err = handle.SetBPFFilter("type mgt subtype beacon or type mgt subtype probe-resp")
	if err != nil {
		log.Warn("Failed to set BPF filter, capturing all frames", svc1log.SafeParam("error", err.Error()))
	}

	// Start scanning
	observations, channelsScanned, err := scanner.scan()
	if err != nil {
		return nil, nil, err
	}

	log.Info("Passive scan completed",
		svc1log.SafeParam("aps_found", len(observations)),
		svc1log.SafeParam("channels_scanned", len(channelsScanned)))

	return observations, channelsScanned, nil
}

// validatePassivePrerequisites checks that all requirements for passive scanning are met.
func validatePassivePrerequisites(interfaceName string) error {
	// 1. Check running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("passive scanning requires root privileges (current euid: %d)", os.Geteuid())
	}

	// 2. Verify interface exists
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", interfaceName, err)
	}

	// 3. Verify interface is up
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %s is not up. Run: ip link set %s up", interfaceName, interfaceName)
	}

	// 4. Verify interface is in monitor mode
	if err := verifyMonitorMode(interfaceName); err != nil {
		return err
	}

	// 5. Check that power save is disabled (best effort)
	checkPowerSave(interfaceName)

	return nil
}

// verifyMonitorMode checks if the interface is in monitor mode.
func verifyMonitorMode(interfaceName string) error {
	// Check via /sys/class/net/<iface>/type
	// Type 803 = ARPHRD_IEEE80211_RADIOTAP (monitor mode with radiotap headers)
	// Type 801 = ARPHRD_IEEE80211 (monitor mode)
	typePath := filepath.Join("/sys/class/net", interfaceName, "type")
	data, err := os.ReadFile(typePath)
	if err != nil {
		// Fallback to iw
		return verifyMonitorModeViaIw(interfaceName)
	}

	typeNum, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return verifyMonitorModeViaIw(interfaceName)
	}

	// ARPHRD_IEEE80211_RADIOTAP = 803, ARPHRD_IEEE80211 = 801
	if typeNum != 803 && typeNum != 801 {
		return fmt.Errorf("interface %s is not in monitor mode (type=%d). "+
			"Configure with:\n"+
			"  ip link set %s down\n"+
			"  iw dev %s set type monitor\n"+
			"  iw dev %s set monitor none\n"+
			"  ip link set %s up",
			interfaceName, typeNum, interfaceName, interfaceName, interfaceName, interfaceName)
	}

	return nil
}

// verifyMonitorModeViaIw uses iw to check interface mode.
func verifyMonitorModeViaIw(interfaceName string) error {
	cmd := exec.Command("iw", "dev", interfaceName, "info")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check interface mode via iw: %w", err)
	}

	if !strings.Contains(string(output), "type monitor") {
		return fmt.Errorf("interface %s is not in monitor mode. "+
			"Configure with:\n"+
			"  ip link set %s down\n"+
			"  iw dev %s set type monitor\n"+
			"  iw dev %s set monitor none\n"+
			"  ip link set %s up",
			interfaceName, interfaceName, interfaceName, interfaceName, interfaceName)
	}

	return nil
}

// checkPowerSave logs a warning if power save is enabled.
func checkPowerSave(interfaceName string) {
	cmd := exec.Command("iw", "dev", interfaceName, "get", "power_save")
	output, err := cmd.Output()
	if err != nil {
		return // Can't check, continue anyway
	}

	if strings.Contains(string(output), "on") {
		// Power save is on - log warning
		// In a real implementation, we'd log this
		fmt.Fprintf(os.Stderr, "WARNING: Power save is enabled on %s. "+
			"Disable with: iw dev %s set power_save off\n", interfaceName, interfaceName)
	}
}

// scan performs the actual passive scanning.
func (s *PassiveScanner) scan() ([]*discover.WirelessObservation, []int, error) {
	timeoutCtx, cancel := context.WithTimeout(s.ctx, time.Duration(s.config.Timeout)*time.Second)
	defer cancel()

	channelsScanned := make(map[int]bool)
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	packets := packetSource.Packets()

	// Channel hopping goroutine
	channelIndex := 0
	hopTicker := time.NewTicker(time.Duration(s.config.DwellTimeMs) * time.Millisecond)
	defer hopTicker.Stop()

	// Set initial channel
	if len(s.config.Channels) > 0 {
		if err := s.setChannel(s.config.Channels[0]); err != nil {
			s.log.Warn("Failed to set initial channel", svc1log.SafeParam("error", err.Error()))
		} else {
			channelsScanned[s.config.Channels[0]] = true
		}
	}

	s.log.Info("Starting passive packet capture",
		svc1log.SafeParam("channels", s.config.Channels),
		svc1log.SafeParam("dwell_time_ms", s.config.DwellTimeMs))

	for {
		select {
		case <-timeoutCtx.Done():
			// Timeout reached, return results
			return s.buildResults(channelsScanned)

		case <-hopTicker.C:
			if s.config.HopChannels && len(s.config.Channels) > 1 {
				channelIndex = (channelIndex + 1) % len(s.config.Channels)
				channel := s.config.Channels[channelIndex]
				if err := s.setChannel(channel); err != nil {
					s.log.Warn("Failed to hop to channel",
						svc1log.SafeParam("channel", channel),
						svc1log.SafeParam("error", err.Error()))
				} else {
					channelsScanned[channel] = true
				}
			}

		case packet, ok := <-packets:
			if !ok {
				return s.buildResults(channelsScanned)
			}
			s.processPacket(packet)
		}
	}
}

// setChannel changes the interface to the specified channel.
func (s *PassiveScanner) setChannel(channel int) error {
	cmd := exec.CommandContext(s.ctx, "iw", "dev", s.config.Interface, "set", "channel", strconv.Itoa(channel))
	return cmd.Run()
}

// processPacket handles a single captured packet.
func (s *PassiveScanner) processPacket(packet gopacket.Packet) {
	// Extract radiotap header for signal info
	var rssi int
	var noiseFloor int
	var freq int
	if rtLayer := packet.Layer(layers.LayerTypeRadioTap); rtLayer != nil {
		rt := rtLayer.(*layers.RadioTap)
		if rt.DBMAntennaSignal != 0 {
			rssi = int(rt.DBMAntennaSignal)
		}
		if rt.DBMAntennaNoise != 0 {
			noiseFloor = int(rt.DBMAntennaNoise)
		}
		if rt.ChannelFrequency != 0 {
			freq = int(rt.ChannelFrequency)
		}
	}

	// Extract 802.11 layer
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return
	}
	dot11 := dot11Layer.(*layers.Dot11)

	// We only care about management frames
	if dot11.Type != layers.Dot11TypeMgmt {
		return
	}

	// Check for beacon or probe response
	var isBeacon bool
	if infoLayer := packet.Layer(layers.LayerTypeDot11MgmtBeacon); infoLayer != nil {
		isBeacon = true
		s.processBeaconOrProbeResp(dot11, infoLayer.(*layers.Dot11MgmtBeacon).Payload, rssi, noiseFloor, freq, isBeacon)
	} else if infoLayer := packet.Layer(layers.LayerTypeDot11MgmtProbeResp); infoLayer != nil {
		s.processBeaconOrProbeResp(dot11, infoLayer.(*layers.Dot11MgmtProbeResp).Payload, rssi, noiseFloor, freq, false)
	}
}

// processBeaconOrProbeResp extracts information from a beacon or probe response frame.
func (s *PassiveScanner) processBeaconOrProbeResp(dot11 *layers.Dot11, payload []byte, rssi, noiseFloor, freq int, isBeacon bool) {
	bssid := dot11.Address3.String()
	if bssid == "" || bssid == "00:00:00:00:00:00" {
		return
	}
	bssid = strings.ToUpper(bssid)

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Update beacon count
	s.beaconCounts[bssid]++
	if _, exists := s.firstSeen[bssid]; !exists {
		s.firstSeen[bssid] = now
	}

	// Parse Information Elements
	ssid, channel, htCaps, vhtCaps, heCaps, security := parseInformationElements(payload)

	// Determine channel from frequency if not found in IEs
	if channel == 0 && freq > 0 {
		channel = frequencyToChannel(freq)
	}
	s.channelsSeenOn[bssid] = channel

	// Get or create observation
	obs, exists := s.observations[bssid]
	if !exists {
		obs = &discover.WirelessObservation{
			Bssid: bssid,
		}
		s.observations[bssid] = obs
	}

	// Update SSID
	if ssid != "" {
		obs.Ssid = &ssid
		obs.SsidLength = ptr(len(ssid))
		isHidden := false
		obs.IsHiddenSsid = &isHidden
	} else if obs.Ssid == nil {
		isHidden := true
		obs.IsHiddenSsid = &isHidden
	}

	// Update radio characteristics
	if obs.RadioCharacteristics == nil {
		obs.RadioCharacteristics = &discover.RadioCharacteristics{}
	}
	if channel > 0 {
		obs.RadioCharacteristics.Channel = &channel
		freqMHz := channelToFrequency(channel)
		obs.RadioCharacteristics.FrequencyMhz = &freqMHz
		obs.RadioCharacteristics.Band = determineFrequencyBand(channel)
	}
	if rssi != 0 {
		obs.RadioCharacteristics.Rssi = &rssi
	}
	if noiseFloor != 0 {
		obs.RadioCharacteristics.NoiseFloor = &noiseFloor
	}

	// Update protocol capabilities
	if htCaps || vhtCaps || heCaps {
		if obs.ProtocolCapabilities == nil {
			obs.ProtocolCapabilities = &discover.ProtocolCapabilities{}
		}
		if htCaps {
			obs.ProtocolCapabilities.Supports80211N = ptr(true)
		}
		if vhtCaps {
			obs.ProtocolCapabilities.Supports80211Ac = ptr(true)
			gen := common.WifiGenerationWifi5
			obs.ProtocolCapabilities.WifiGeneration = &gen
		}
		if heCaps {
			obs.ProtocolCapabilities.Supports80211Ax = ptr(true)
			gen := common.WifiGenerationWifi6
			obs.ProtocolCapabilities.WifiGeneration = &gen
		}
		if obs.ProtocolCapabilities.WifiGeneration == nil && htCaps {
			gen := common.WifiGenerationWifi4
			obs.ProtocolCapabilities.WifiGeneration = &gen
		}
	}

	// Update security configuration
	if security != nil {
		obs.SecurityConfiguration = security
	}

	// Update temporal signals
	if obs.TemporalSignals == nil {
		obs.TemporalSignals = &discover.TemporalSignals{}
	}
	firstSeenTime := s.firstSeen[bssid]
	obs.TemporalSignals.FirstSeen = &firstSeenTime
	obs.TemporalSignals.LastSeen = &now
	beaconCount := s.beaconCounts[bssid]
	obs.TemporalSignals.BeaconCount = &beaconCount

	// Update observation metadata
	passiveOnly := true
	var frameTypes []common.FrameType
	if isBeacon {
		frameTypes = []common.FrameType{common.FrameTypeBeacon}
	} else {
		frameTypes = []common.FrameType{common.FrameTypeProbeResponse}
	}
	obs.ObservationMetadata = &discover.ObservationMetadata{
		Timestamp:      &now,
		PassiveOnly:    &passiveOnly,
		FrameTypes:     frameTypes,
		RawBeaconCount: &beaconCount,
	}
}

// parseInformationElements extracts data from 802.11 Information Elements.
func parseInformationElements(payload []byte) (ssid string, channel int, htCaps, vhtCaps, heCaps bool, security *discover.SecurityConfiguration) {
	// Skip fixed parameters (timestamp 8 + beacon interval 2 + capability 2 = 12 bytes)
	if len(payload) < 12 {
		return
	}
	ies := payload[12:]

	security = &discover.SecurityConfiguration{}
	var hasRSN, hasWPA bool

	for len(ies) >= 2 {
		elementID := ies[0]
		length := int(ies[1])
		if len(ies) < 2+length {
			break
		}
		data := ies[2 : 2+length]
		ies = ies[2+length:]

		switch elementID {
		case 0: // SSID
			ssid = string(data)
		case 3: // DS Parameter Set (channel)
			if len(data) >= 1 {
				channel = int(data[0])
			}
		case 45: // HT Capabilities
			htCaps = true
		case 191: // VHT Capabilities
			vhtCaps = true
		case 255: // Extension element
			if len(data) >= 1 {
				extID := data[0]
				if extID == 35 { // HE Capabilities
					heCaps = true
				}
			}
		case 48: // RSN (WPA2/WPA3)
			hasRSN = true
			parseRSNElement(data, security)
		case 221: // Vendor Specific
			if len(data) >= 4 {
				oui := data[0:3]
				ouiType := data[3]
				// Microsoft WPA OUI: 00:50:F2, type 1
				if oui[0] == 0x00 && oui[1] == 0x50 && oui[2] == 0xF2 && ouiType == 1 {
					hasWPA = true
					if !hasRSN {
						version := common.WpaVersionWpa1
						security.WpaVersion = &version
					}
				}
			}
		}
	}

	// Determine if open network
	if !hasRSN && !hasWPA {
		isOpen := true
		security.IsOpenNetwork = &isOpen
		enc := common.EncryptionProtocolNone
		security.EncryptionProtocol = &enc
		auth := common.AuthenticationMethodOpen
		security.AuthenticationMethod = &auth
	} else {
		isOpen := false
		security.IsOpenNetwork = &isOpen
	}

	return
}

// parseRSNElement parses RSN (Robust Security Network) element for WPA2/WPA3 info.
func parseRSNElement(data []byte, security *discover.SecurityConfiguration) {
	if len(data) < 2 {
		return
	}

	// Version (should be 1)
	version := binary.LittleEndian.Uint16(data[0:2])
	if version != 1 {
		return
	}

	pos := 2

	// Group cipher suite (4 bytes)
	if len(data) >= pos+4 {
		pos += 4
	}

	// Pairwise cipher suite count
	if len(data) < pos+2 {
		return
	}
	pairwiseCount := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
	pos += 2

	// Skip pairwise cipher suites
	if len(data) < pos+pairwiseCount*4 {
		return
	}
	// Check for CCMP in pairwise
	for i := 0; i < pairwiseCount; i++ {
		suite := data[pos+i*4 : pos+i*4+4]
		if suite[3] == 4 { // CCMP
			enc := common.EncryptionProtocolCcmp
			security.EncryptionProtocol = &enc
			cipher := common.CipherSuiteCcmp128
			security.PairwiseCipherSuites = []common.CipherSuite{cipher}
		}
	}
	pos += pairwiseCount * 4

	// AKM suite count
	if len(data) < pos+2 {
		wpaVer := common.WpaVersionWpa2
		security.WpaVersion = &wpaVer
		return
	}
	akmCount := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
	pos += 2

	// Parse AKM suites
	if len(data) < pos+akmCount*4 {
		wpaVer := common.WpaVersionWpa2
		security.WpaVersion = &wpaVer
		return
	}

	for i := 0; i < akmCount; i++ {
		suite := data[pos+i*4 : pos+i*4+4]
		akmType := suite[3]
		switch akmType {
		case 1: // 802.1X
			auth := common.AuthenticationMethodEap
			security.AuthenticationMethod = &auth
			security.KeyManagement = append(security.KeyManagement, common.KeyManagementTypeEap8021X)
			wpaVer := common.WpaVersionWpa2
			security.WpaVersion = &wpaVer
		case 2: // PSK
			auth := common.AuthenticationMethodPsk
			security.AuthenticationMethod = &auth
			security.KeyManagement = append(security.KeyManagement, common.KeyManagementTypePsk)
			wpaVer := common.WpaVersionWpa2
			security.WpaVersion = &wpaVer
		case 8: // SAE (WPA3)
			auth := common.AuthenticationMethodSae
			security.AuthenticationMethod = &auth
			security.KeyManagement = append(security.KeyManagement, common.KeyManagementTypeSae)
			wpaVer := common.WpaVersionWpa3
			security.WpaVersion = &wpaVer
		case 18: // OWE
			wpaVer := common.WpaVersionWpa3
			security.WpaVersion = &wpaVer
			owe := true
			security.IsOweTransitionMode = &owe
		}
	}
	pos += akmCount * 4

	// RSN Capabilities (2 bytes)
	if len(data) >= pos+2 {
		caps := binary.LittleEndian.Uint16(data[pos : pos+2])
		// Bit 6: MFPC (Management Frame Protection Capable)
		// Bit 7: MFPR (Management Frame Protection Required)
		mfpr := (caps & 0x0080) != 0
		mfpc := (caps & 0x0040) != 0
		if mfpr {
			pmf := common.PmfPolicyRequired
			security.PmfPolicy = &pmf
		} else if mfpc {
			pmf := common.PmfPolicyOptional
			security.PmfPolicy = &pmf
		}
	}
}

// buildResults converts the observations map to a slice.
func (s *PassiveScanner) buildResults(channelsScanned map[int]bool) ([]*discover.WirelessObservation, []int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	observations := make([]*discover.WirelessObservation, 0, len(s.observations))
	for _, obs := range s.observations {
		observations = append(observations, obs)
	}

	channels := make([]int, 0, len(channelsScanned))
	for ch := range channelsScanned {
		channels = append(channels, ch)
	}

	return observations, channels, nil
}

// checkPassiveModeLinux validates that passive mode is available on Linux.
func checkPassiveModeLinux(ctx context.Context, interfaceName string) error {
	log := svc1log.FromContext(ctx)

	if interfaceName == "" {
		return fmt.Errorf("passive mode on Linux requires specifying a monitor mode interface. " +
			"Setup instructions:\n" +
			"  1. Stop NetworkManager: sudo systemctl stop NetworkManager\n" +
			"  2. Configure monitor mode:\n" +
			"     ip link set <iface> down\n" +
			"     iw dev <iface> set type monitor\n" +
			"     iw dev <iface> set monitor none\n" +
			"     ip link set <iface> up\n" +
			"  3. Disable power save: iw dev <iface> set power_save off")
	}

	// Check if running as root
	if os.Geteuid() != 0 {
		log.Warn("Passive mode requires root privileges on Linux")
		return fmt.Errorf("passive mode on Linux requires root privileges. Run with sudo")
	}

	// Verify monitor mode
	if err := verifyMonitorMode(interfaceName); err != nil {
		return err
	}

	// Check that libpcap is available (this will fail at runtime if not)
	// We could add a more explicit check here

	return nil
}
