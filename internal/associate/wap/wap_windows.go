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

	"github.com/Method-Security/infrascan/generated/go/associate"
	"github.com/Method-Security/infrascan/generated/go/common"
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
func reconnectToOriginalNetwork(ctx context.Context, interfaceName string, original *associate.OriginalNetworkState) error {
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
	cred *associate.TestClientProfile,
	timeout int,
) *ConnectionResult {
	log := svc1log.FromContext(ctx)
	result := NewConnectionResult()

	iface := interfaceName
	if iface == "" {
		var err error
		iface, err = findWirelessInterface(ctx)
		if err != nil {
			result.WithError(associate.AssociationOutcomeInterfaceError, err.Error())
			return result
		}
	}

	switch cred.CredentialType {
	case associate.TestCredentialTypeNone:
		// Open network connection
		result = connectWithNetsh(ctx, iface, targetSSID, "", timeout)

	case associate.TestCredentialTypePskSimple, associate.TestCredentialTypePskCommon:
		// PSK connection
		if cred.Psk == nil || *cred.Psk == "" {
			result.WithError(associate.AssociationOutcomeAuthFailed, "PSK credential required but not provided")
			return result
		}
		result = connectWithNetsh(ctx, iface, targetSSID, *cred.Psk, timeout)

	case associate.TestCredentialTypeEapTestIdentity, associate.TestCredentialTypeEapGuest:
		// EAP connection - requires profile creation
		log.Warn("EAP connection on Windows requires pre-configured profiles")
		result.WithError(associate.AssociationOutcomeDriverError, "EAP connection requires pre-configured Windows profiles")

	default:
		result.WithError(associate.AssociationOutcomeUnknownError, fmt.Sprintf("unsupported credential type: %s", cred.CredentialType))
	}

	// If connection succeeded, get additional info
	if result.Outcome == associate.AssociationOutcomeSuccess {
		// Get DHCP info
		ipAcquired, ip, gateway, dns := waitForDHCPWindows(ctx, iface, timeout)
		result.IpAcquired = &ipAcquired
		if ip != "" {
			result.IpAddress = &ip
		}
		if gateway != "" {
			result.Gateway = &gateway
		}
		if len(dns) > 0 {
			result.DnsServers = dns
		}

		// Check for captive portal
		if ipAcquired {
			portalDetected, portalURL := detectCaptivePortalWindows(ctx)
			result.PortalDetected = &portalDetected
			if portalURL != "" {
				result.PortalUrl = &portalURL
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
			result.WithError(associate.AssociationOutcomeDriverError, fmt.Sprintf("Failed to create profile: %v", err))
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
			result.WithError(associate.AssociationOutcomeNetworkNotFound, "Network not found")
		} else {
			result.WithError(associate.AssociationOutcomeAssocFailed, outputStr)
		}
		return result
	}

	// Wait for connection to establish
	time.Sleep(3 * time.Second)

	// Verify connection
	currentSSID, _, connected := getCurrentConnection(ctx, iface)
	if connected && currentSSID == ssid {
		result.WithSuccess()

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
			result.WithError(associate.AssociationOutcomeAssocFailed, "Connection not established")
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
func getSecurityInfoWindows(ctx context.Context, iface string) *associate.NegotiatedSecurity {
	cmd := exec.Command("netsh", "wlan", "show", "interfaces")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	negSec := &associate.NegotiatedSecurity{}
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

