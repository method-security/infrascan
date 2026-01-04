//go:build windows

package wap

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/Method-Security/infrascan/generated/go/common"
	"github.com/Method-Security/infrascan/generated/go/connect"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// findWirelessInterface finds an available wireless interface on Windows.
func findWirelessInterface(ctx context.Context) (string, error) {
	// Use netsh to list wireless interfaces
	cmd := exec.Command("netsh", "wlan", "show", "interfaces")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to list wireless interfaces: %w", err)
	}

	// Parse output to find interface name
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	return "", fmt.Errorf("no wireless interface found")
}

// getCurrentConnection returns the current WiFi connection info on Windows.
// getConnectionProfileName returns the saved WiFi profile name on Windows.
// On Windows, the profile name is typically the same as the SSID.
func getConnectionProfileName(ctx context.Context, interfaceName string) string {
	// On Windows, get current SSID - profile names typically match
	ssid, _, connected := getCurrentConnection(ctx, interfaceName)
	if connected {
		return ssid
	}
	return ""
}

func getCurrentConnection(ctx context.Context, interfaceName string) (ssid string, bssid string, connected bool) {
	cmd := exec.Command("netsh", "wlan", "show", "interfaces")
	output, err := cmd.Output()
	if err != nil {
		return "", "", false
	}

	lines := strings.Split(string(output), "\n")
	inTargetInterface := interfaceName == ""
	currentState := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check if we're in the right interface section
		if strings.HasPrefix(line, "Name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[1])
				inTargetInterface = interfaceName == "" || name == interfaceName
			}
		}

		if !inTargetInterface {
			continue
		}

		// Parse state
		if strings.HasPrefix(line, "State") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentState = strings.TrimSpace(parts[1])
			}
		}

		// Parse SSID
		if strings.HasPrefix(line, "SSID") && !strings.HasPrefix(line, "BSSID") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ssid = strings.TrimSpace(parts[1])
			}
		}

		// Parse BSSID
		if strings.HasPrefix(line, "BSSID") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				// BSSID contains colons, so we need to rejoin
				bssid = strings.ToUpper(strings.TrimSpace(parts[1]))
			}
		}
	}

	connected = strings.ToLower(currentState) == "connected"
	return ssid, bssid, connected
}

// getSignalQuality returns the signal quality for a target network on Windows.
func getSignalQuality(ctx context.Context, interfaceName string, targetSSID string, targetBSSID string) int {
	// Check current connection first
	currentSSID, _, connected := getCurrentConnection(ctx, interfaceName)
	if connected && currentSSID == targetSSID {
		cmd := exec.Command("netsh", "wlan", "show", "interfaces")
		output, err := cmd.Output()
		if err == nil {
			signalRegex := regexp.MustCompile(`Signal\s*:\s*(\d+)%`)
			if match := signalRegex.FindStringSubmatch(string(output)); len(match) > 1 {
				var signal int
				fmt.Sscanf(match[1], "%d", &signal)
				// Convert percentage to approximate dBm
				return -100 + (signal * 70 / 100)
			}
		}
	}

	// Scan for networks
	cmd := exec.Command("netsh", "wlan", "show", "networks", "mode=bssid")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	lines := strings.Split(string(output), "\n")
	currentSSIDInScan := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "SSID") && !strings.HasPrefix(line, "BSSID") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentSSIDInScan = strings.TrimSpace(parts[1])
			}
		}

		if currentSSIDInScan == targetSSID && strings.HasPrefix(line, "Signal") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				signalStr := strings.TrimSpace(strings.TrimSuffix(parts[1], "%"))
				var signal int
				fmt.Sscanf(signalStr, "%d", &signal)
				return -100 + (signal * 70 / 100)
			}
		}
	}

	return 0
}

// disconnectFromNetwork disconnects from the current WiFi network on Windows.
func disconnectFromNetwork(ctx context.Context, interfaceName string) error {
	iface := interfaceName
	if iface == "" {
		var err error
		iface, err = findWirelessInterface(ctx)
		if err != nil {
			return err
		}
	}

	cmd := exec.Command("netsh", "wlan", "disconnect", "interface="+iface)
	return cmd.Run()
}

// reconnectToOriginalNetwork reconnects to the original WiFi network on Windows.
func reconnectToOriginalNetwork(ctx context.Context, interfaceName string, original *connect.OriginalNetworkState) error {
	if original == nil || !original.WasConnected {
		return nil
	}

	log := svc1log.FromContext(ctx)
	iface := interfaceName
	if iface == "" {
		var err error
		iface, err = findWirelessInterface(ctx)
		if err != nil {
			return err
		}
	}

	ssid := ""
	if original.Ssid != nil {
		ssid = *original.Ssid
	}

	if ssid == "" {
		return fmt.Errorf("original network SSID not available")
	}

	log.Info("Reconnecting to original network",
		svc1log.SafeParam("ssid", ssid))

	// Use netsh to connect to saved profile
	cmd := exec.Command("netsh", "wlan", "connect", "name="+ssid, "interface="+iface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to reconnect: %s - %w", string(output), err)
	}

	// Wait and verify connection
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		currentSSID, _, connected := getCurrentConnection(ctx, iface)
		if connected && currentSSID == ssid {
			return nil
		}
	}

	return fmt.Errorf("failed to verify reconnection to original network")
}

// connectToNetwork performs the actual connection attempt on Windows.
func connectToNetwork(
	ctx context.Context,
	interfaceName string,
	targetSSID string,
	targetBSSID string,
	cred *connect.TestClientProfile,
	timeout int,
) *ConnectionResult {
	log := svc1log.FromContext(ctx)
	result := NewConnectionResult()

	iface := interfaceName
	if iface == "" {
		var err error
		iface, err = findWirelessInterface(ctx)
		if err != nil {
			result.WithError(connect.ConnectionOutcomeInterfaceError, err.Error())
			return result
		}
	}

	switch cred.CredentialType {
	case connect.TestCredentialTypeNone:
		// Open network connection
		result = connectWithNetsh(ctx, iface, targetSSID, "", timeout)

	case connect.TestCredentialTypePskSimple, connect.TestCredentialTypePskCommon:
		// PSK connection
		if cred.Psk == nil || *cred.Psk == "" {
			result.WithError(connect.ConnectionOutcomeAuthFailed, "PSK credential required but not provided")
			return result
		}
		result = connectWithNetsh(ctx, iface, targetSSID, *cred.Psk, timeout)

	case connect.TestCredentialTypeEapTestIdentity, connect.TestCredentialTypeEapGuest:
		// EAP connection - requires profile creation
		log.Warn("EAP connection on Windows requires pre-configured profiles")
		result.WithError(connect.ConnectionOutcomeDriverError, "EAP connection requires pre-configured Windows profiles")

	default:
		result.WithError(connect.ConnectionOutcomeUnknownError, fmt.Sprintf("unsupported credential type: %s", cred.CredentialType))
	}

	// If connection succeeded, get additional info
	if result.Outcome == connect.ConnectionOutcomeSuccess {
		// Get DHCP info
		ipAcquired, ip, gateway, dns := waitForDHCPWindows(ctx, iface, timeout)
		result.IPAcquired = &ipAcquired
		if ip != "" {
			result.IPAddress = &ip
		}
		if gateway != "" {
			result.Gateway = &gateway
		}
		if len(dns) > 0 {
			result.DNSServers = dns
		}

		// Check for captive portal
		if ipAcquired {
			portalDetected, portalURL := detectCaptivePortalWindows(ctx)
			result.PortalDetected = &portalDetected
			if portalURL != "" {
				result.PortalURL = &portalURL
			}
		}
	}

	return result
}

// connectWithNetsh connects using netsh wlan commands.
func connectWithNetsh(ctx context.Context, iface, ssid, password string, timeout int) *ConnectionResult {
	log := svc1log.FromContext(ctx)
	result := NewConnectionResult()

	// Check if profile exists
	profileExists := checkProfileExists(ssid)

	if !profileExists {
		// Create temporary profile
		if err := createWlanProfile(ssid, password); err != nil {
			result.WithError(connect.ConnectionOutcomeDriverError, fmt.Sprintf("Failed to create profile: %v", err))
			return result
		}
		defer deleteWlanProfile(ssid)
	}

	log.Info("Connecting with netsh", svc1log.SafeParam("ssid", ssid))

	// Connect to the network
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "netsh", "wlan", "connect", "name="+ssid, "interface="+iface)
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if err != nil {
		if timeoutCtx.Err() == context.DeadlineExceeded {
			result.WithTimeout("Connection timed out")
		} else if strings.Contains(outputStr, "is not visible") {
			result.WithError(connect.ConnectionOutcomeNetworkNotFound, "Network not found")
		} else {
			result.WithError(connect.ConnectionOutcomeAssocFailed, outputStr)
		}
		return result
	}

	// Wait for connection to establish
	time.Sleep(3 * time.Second)

	// Verify connection
	currentSSID, currentBSSID, connected := getCurrentConnection(ctx, iface)
	if connected && currentSSID == ssid {
		result.WithSuccess()

		// Store the actual connected BSSID
		if currentBSSID != "" {
			result.ConnectedBSSID = &currentBSSID
			log.Debug("Connected to BSSID", svc1log.SafeParam("bssid", currentBSSID))
		}

		// Get security info
		negSec := getSecurityInfoWindows(ctx, iface)
		if negSec != nil {
			result.NegotiatedSecurity = negSec
		}
	} else {
		// Check for authentication failure
		cmd = exec.Command("netsh", "wlan", "show", "interfaces")
		output, _ = cmd.Output()
		if strings.Contains(string(output), "Authentication") {
			result.WithAuthFailed("Authentication failed")
		} else {
			result.WithError(connect.ConnectionOutcomeAssocFailed, "Connection not established")
		}
	}

	return result
}

// checkProfileExists checks if a WLAN profile exists.
func checkProfileExists(ssid string) bool {
	cmd := exec.Command("netsh", "wlan", "show", "profile", "name="+ssid)
	return cmd.Run() == nil
}

// createWlanProfile creates a temporary WLAN profile.
func createWlanProfile(ssid, password string) error {
	var profileXML string

	if password == "" {
		// Open network profile
		profileXML = fmt.Sprintf(`<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>%s</name>
    <SSIDConfig>
        <SSID>
            <name>%s</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>`, ssid, ssid)
	} else {
		// WPA2-Personal profile
		profileXML = fmt.Sprintf(`<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>%s</name>
    <SSIDConfig>
        <SSID>
            <name>%s</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>%s</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>`, ssid, ssid, password)
	}

	// Write profile to temp file and import
	cmd := exec.Command("netsh", "wlan", "add", "profile", "filename=-")
	cmd.Stdin = strings.NewReader(profileXML)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add profile: %s - %w", string(output), err)
	}

	return nil
}

// deleteWlanProfile deletes a WLAN profile.
func deleteWlanProfile(ssid string) {
	exec.Command("netsh", "wlan", "delete", "profile", "name="+ssid).Run()
}

// getSecurityInfoWindows retrieves negotiated security info on Windows.
func getSecurityInfoWindows(ctx context.Context, iface string) *connect.NegotiatedSecurity {
	cmd := exec.Command("netsh", "wlan", "show", "interfaces")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	negSec := &connect.NegotiatedSecurity{}
	outputStr := string(output)

	// Parse authentication type
	authRegex := regexp.MustCompile(`Authentication\s*:\s*(.+)`)
	if match := authRegex.FindStringSubmatch(outputStr); len(match) > 1 {
		auth := strings.TrimSpace(match[1])
		if strings.Contains(auth, "WPA3") {
			wpaVer := common.WpaVersionWpa3
			negSec.WpaVersion = (*common.WpaVersion)(&wpaVer)
			authMethod := common.AuthenticationMethodSae
			negSec.AuthenticationMethod = (*common.AuthenticationMethod)(&authMethod)
			pmf := true
			negSec.PmfNegotiated = &pmf
		} else if strings.Contains(auth, "WPA2") {
			wpaVer := common.WpaVersionWpa2
			negSec.WpaVersion = (*common.WpaVersion)(&wpaVer)
		} else if strings.Contains(auth, "WPA") {
			wpaVer := common.WpaVersionWpa1
			negSec.WpaVersion = (*common.WpaVersion)(&wpaVer)
		} else if strings.Contains(auth, "Open") {
			authMethod := common.AuthenticationMethodOpen
			negSec.AuthenticationMethod = (*common.AuthenticationMethod)(&authMethod)
		}
	}

	// Parse cipher
	cipherRegex := regexp.MustCompile(`Cipher\s*:\s*(.+)`)
	if match := cipherRegex.FindStringSubmatch(outputStr); len(match) > 1 {
		cipher := strings.TrimSpace(match[1])
		if strings.Contains(cipher, "CCMP") {
			enc := common.EncryptionProtocolCcmp
			negSec.EncryptionProtocol = (*common.EncryptionProtocol)(&enc)
			pairwise := common.CipherSuiteCcmp128
			negSec.PairwiseCipher = (*common.CipherSuite)(&pairwise)
		} else if strings.Contains(cipher, "GCMP") {
			enc := common.EncryptionProtocolGcmp
			negSec.EncryptionProtocol = (*common.EncryptionProtocol)(&enc)
		} else if strings.Contains(cipher, "TKIP") {
			enc := common.EncryptionProtocolTkip
			negSec.EncryptionProtocol = (*common.EncryptionProtocol)(&enc)
		}
	}

	return negSec
}

// waitForDHCPWindows waits for DHCP to assign an IP address on Windows.
func waitForDHCPWindows(ctx context.Context, iface string, timeout int) (acquired bool, ip string, gateway string, dns []string) {
	log := svc1log.FromContext(ctx)
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)

	for time.Now().Before(deadline) {
		// Get IP configuration using ipconfig
		cmd := exec.Command("ipconfig", "/all")
		output, err := cmd.Output()
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}

		outputStr := string(output)
		// Find the section for our interface
		sections := strings.Split(outputStr, "\r\n\r\n")
		for _, section := range sections {
			if !strings.Contains(section, iface) {
				continue
			}

			// Parse IPv4 address
			ipRegex := regexp.MustCompile(`IPv4 Address[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)`)
			if match := ipRegex.FindStringSubmatch(section); len(match) > 1 {
				ip = match[1]
				if !strings.HasPrefix(ip, "169.254.") { // Not link-local
					// Get gateway
					gwRegex := regexp.MustCompile(`Default Gateway[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)`)
					if match := gwRegex.FindStringSubmatch(section); len(match) > 1 {
						gateway = match[1]
					}

					// Get DNS
					dnsRegex := regexp.MustCompile(`DNS Servers[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)`)
					dnsMatches := dnsRegex.FindAllStringSubmatch(section, -1)
					for _, m := range dnsMatches {
						if len(m) > 1 {
							dns = append(dns, m[1])
						}
					}

					log.Info("DHCP lease acquired",
						svc1log.SafeParam("ip", ip),
						svc1log.SafeParam("gateway", gateway))
					return true, ip, gateway, dns
				}
			}
		}
		time.Sleep(1 * time.Second)
	}

	log.Warn("DHCP timeout - no IP acquired")
	return false, "", "", nil
}

// detectCaptivePortalWindows checks for captive portal on Windows.
func detectCaptivePortalWindows(ctx context.Context) (detected bool, portalURL string) {
	log := svc1log.FromContext(ctx)

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Windows uses NCSI (Network Connectivity Status Indicator)
	resp, err := client.Get("http://www.msftconnecttest.com/connecttest.txt")
	if err != nil {
		log.Debug("Captive portal check failed", svc1log.SafeParam("error", err.Error()))
		return false, ""
	}
	defer resp.Body.Close()

	// Redirect indicates captive portal
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		return true, location
	}

	// Check response - should be "Microsoft Connect Test"
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Microsoft Connect Test") {
		return true, ""
	}

	return false, ""
}

// detectNetworkSecurity detects the security type of a target wireless network on Windows.
// Uses netsh wlan show networks to scan for the network and determine its security configuration.
func detectNetworkSecurity(ctx context.Context, interfaceName string, targetSSID string, targetBSSID string) NetworkSecurityType {
	log := svc1log.FromContext(ctx)

	// Use netsh to list networks
	cmd := exec.Command("netsh", "wlan", "show", "networks", "mode=bssid")
	output, err := cmd.Output()
	if err != nil {
		log.Warn("Failed to list networks for security detection",
			svc1log.SafeParam("error", err.Error()))
		return NetworkSecurityUnknown
	}

	// Parse netsh output
	// Format:
	// SSID 1 : NetworkName
	//     Network type            : Infrastructure
	//     Authentication          : WPA2-Personal
	//     Encryption              : CCMP
	//     BSSID 1                 : xx:xx:xx:xx:xx:xx
	//         Signal              : 100%
	//         ...

	lines := strings.Split(string(output), "\n")
	var currentSSID string
	var currentAuth string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// SSID line
		if strings.HasPrefix(line, "SSID") && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentSSID = strings.TrimSpace(parts[1])
			}
			continue
		}

		// Authentication line
		if strings.HasPrefix(line, "Authentication") && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentAuth = strings.TrimSpace(parts[1])
			}
			continue
		}

		// BSSID line
		if strings.HasPrefix(line, "BSSID") && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				bssid := strings.ToUpper(strings.TrimSpace(parts[1]))

				// Check if this matches our target
				matchSSID := targetSSID != "" && currentSSID == targetSSID
				matchBSSID := targetBSSID != "" && strings.EqualFold(bssid, targetBSSID)

				if matchSSID || matchBSSID {
					log.Debug("Found target network security",
						svc1log.SafeParam("ssid", currentSSID),
						svc1log.SafeParam("authentication", currentAuth))

					return parseWindowsAuthType(currentAuth)
				}
			}
		}
	}

	log.Warn("Target network not found in scan results",
		svc1log.SafeParam("target_ssid", targetSSID),
		svc1log.SafeParam("target_bssid", targetBSSID))
	return NetworkSecurityUnknown
}

// parseWindowsAuthType parses the authentication string from netsh output.
func parseWindowsAuthType(auth string) NetworkSecurityType {
	auth = strings.ToUpper(auth)

	// Open network
	if auth == "OPEN" || auth == "" {
		return NetworkSecurityOpen
	}

	// Enterprise variants
	if strings.Contains(auth, "ENTERPRISE") || strings.Contains(auth, "802.1X") {
		return NetworkSecurityEAP
	}

	// Personal/PSK variants
	if strings.Contains(auth, "PERSONAL") || strings.Contains(auth, "PSK") {
		return NetworkSecurityPSK
	}

	// WPA/WPA2/WPA3 without qualifier - check for common patterns
	if strings.HasPrefix(auth, "WPA") {
		// WPA2-Personal, WPA3-Personal, etc.
		if strings.Contains(auth, "PERSONAL") {
			return NetworkSecurityPSK
		}
		// Default to PSK for WPA without explicit enterprise
		return NetworkSecurityPSK
	}

	// WEP
	if strings.Contains(auth, "WEP") {
		return NetworkSecurityPSK
	}

	return NetworkSecurityUnknown
}
