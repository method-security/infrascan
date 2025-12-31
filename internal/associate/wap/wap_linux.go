//go:build linux

package wap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/Method-Security/infrascan/generated/go/associate"
	"github.com/Method-Security/infrascan/generated/go/common"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// findWirelessInterface finds an available wireless interface on Linux.
func findWirelessInterface(ctx context.Context) (string, error) {
	// Try to get wireless interfaces using iw
	cmd := exec.Command("iw", "dev")
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "Interface ") {
				return strings.TrimPrefix(line, "Interface "), nil
			}
		}
	}

	// Fall back to common interface names
	commonInterfaces := []string{"wlan0", "wlp2s0", "wlp3s0", "wlan1", "wlo1", "wlp4s0"}
	for _, iface := range commonInterfaces {
		cmd := exec.Command("ip", "link", "show", iface)
		if err := cmd.Run(); err == nil {
			return iface, nil
		}
	}

	return "", fmt.Errorf("no wireless interface found; please specify one with --interface")
}

// getCurrentConnection returns the current WiFi connection info on Linux.
func getCurrentConnection(ctx context.Context, interfaceName string) (ssid string, bssid string, connected bool) {
	iface := interfaceName
	if iface == "" {
		var err error
		iface, err = findWirelessInterface(ctx)
		if err != nil {
			return "", "", false
		}
	}

	// Try nmcli first (most reliable on modern systems)
	cmd := exec.Command("nmcli", "-t", "-f", "DEVICE,STATE,CONNECTION", "device", "status")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 && parts[0] == iface && parts[1] == "connected" {
				ssid = parts[2]
				// Get BSSID
				bssidCmd := exec.Command("iw", "dev", iface, "link")
				bssidOutput, _ := bssidCmd.Output()
				bssidRegex := regexp.MustCompile(`Connected to ([0-9a-fA-F:]+)`)
				if match := bssidRegex.FindStringSubmatch(string(bssidOutput)); len(match) > 1 {
					bssid = strings.ToUpper(match[1])
				}
				return ssid, bssid, true
			}
		}
	}

	// Try iw directly
	cmd = exec.Command("iw", "dev", iface, "link")
	output, err = cmd.Output()
	if err == nil {
		outputStr := string(output)
		if !strings.Contains(outputStr, "Not connected") {
			// Parse SSID
			ssidRegex := regexp.MustCompile(`SSID: (.+)`)
			if match := ssidRegex.FindStringSubmatch(outputStr); len(match) > 1 {
				ssid = match[1]
			}
			// Parse BSSID
			bssidRegex := regexp.MustCompile(`Connected to ([0-9a-fA-F:]+)`)
			if match := bssidRegex.FindStringSubmatch(outputStr); len(match) > 1 {
				bssid = strings.ToUpper(match[1])
			}
			return ssid, bssid, ssid != ""
		}
	}

	return "", "", false
}

// getSignalQuality returns the RSSI for a target network on Linux.
func getSignalQuality(ctx context.Context, interfaceName string, targetSSID string, targetBSSID string) int {
	iface := interfaceName
	if iface == "" {
		var err error
		iface, err = findWirelessInterface(ctx)
		if err != nil {
			return 0
		}
	}

	// Check if we're connected to this network
	currentSSID, _, connected := getCurrentConnection(ctx, iface)
	if connected && currentSSID == targetSSID {
		// Get signal from iw
		cmd := exec.Command("iw", "dev", iface, "link")
		output, err := cmd.Output()
		if err == nil {
			signalRegex := regexp.MustCompile(`signal: (-?\d+) dBm`)
			if match := signalRegex.FindStringSubmatch(string(output)); len(match) > 1 {
				var rssi int
				fmt.Sscanf(match[1], "%d", &rssi)
				return rssi
			}
		}
	}

	// Otherwise, do a scan
	cmd := exec.Command("nmcli", "-t", "-f", "SSID,SIGNAL", "device", "wifi", "list", "--rescan", "no")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 && parts[0] == targetSSID {
				var signal int
				fmt.Sscanf(parts[1], "%d", &signal)
				// Convert percentage to approximate dBm
				return -100 + (signal * 70 / 100)
			}
		}
	}

	return 0
}

// disconnectFromNetwork disconnects from the current WiFi network on Linux.
func disconnectFromNetwork(ctx context.Context, interfaceName string) error {
	iface := interfaceName
	if iface == "" {
		var err error
		iface, err = findWirelessInterface(ctx)
		if err != nil {
			return err
		}
	}

	// Try nmcli first
	cmd := exec.Command("nmcli", "device", "disconnect", iface)
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Fall back to iw
	cmd = exec.Command("iw", "dev", iface, "disconnect")
	return cmd.Run()
}

// reconnectToOriginalNetwork reconnects to the original WiFi network on Linux.
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

	log.Info("Reconnecting to original network using nmcli",
		svc1log.SafeParam("ssid", ssid))

	// Try nmcli to connect to known network
	cmd := exec.Command("nmcli", "device", "wifi", "connect", ssid, "ifname", iface)
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

// connectToNetwork performs the actual connection attempt on Linux.
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

	// Check if we have nmcli (NetworkManager)
	hasNmcli := checkCommandExists("nmcli")
	hasWpaSupplicant := checkCommandExists("wpa_supplicant")

	switch cred.CredentialType {
	case associate.TestCredentialTypeNone:
		// Open network connection
		if hasNmcli {
			result = connectWithNmcli(ctx, iface, targetSSID, targetBSSID, "", timeout)
		} else if hasWpaSupplicant {
			result = connectWithWpaSupplicant(ctx, iface, targetSSID, "", timeout)
		} else {
			result.WithError(associate.AssociationOutcomeDriverError, "Neither nmcli nor wpa_supplicant available")
		}

	case associate.TestCredentialTypePskSimple, associate.TestCredentialTypePskCommon:
		// PSK connection
		if cred.Psk == nil || *cred.Psk == "" {
			result.WithError(associate.AssociationOutcomeAuthFailed, "PSK credential required but not provided")
			return result
		}
		if hasNmcli {
			result = connectWithNmcli(ctx, iface, targetSSID, targetBSSID, *cred.Psk, timeout)
		} else if hasWpaSupplicant {
			result = connectWithWpaSupplicant(ctx, iface, targetSSID, *cred.Psk, timeout)
		} else {
			result.WithError(associate.AssociationOutcomeDriverError, "Neither nmcli nor wpa_supplicant available")
		}

	case associate.TestCredentialTypeEapTestIdentity, associate.TestCredentialTypeEapGuest:
		// EAP connection
		if cred.EapIdentity == nil || *cred.EapIdentity == "" {
			result.WithError(associate.AssociationOutcomeAuthFailed, "EAP identity required but not provided")
			return result
		}
		if hasNmcli {
			result = connectWithNmcliEAP(ctx, iface, targetSSID, *cred.EapIdentity, ptrStr(cred.EapPassword), timeout)
		} else {
			log.Warn("EAP connection without nmcli is not supported")
			result.WithError(associate.AssociationOutcomeDriverError, "EAP connection requires nmcli")
		}

	default:
		result.WithError(associate.AssociationOutcomeUnknownError, fmt.Sprintf("unsupported credential type: %s", cred.CredentialType))
	}

	// If connection succeeded, get additional info
	if result.Outcome == associate.AssociationOutcomeSuccess {
		// Get DHCP info
		ipAcquired, ip, gateway, dns := waitForDHCPLinux(ctx, iface, timeout)
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
			portalDetected, portalURL := detectCaptivePortalLinux(ctx)
			result.PortalDetected = &portalDetected
			if portalURL != "" {
				result.PortalUrl = &portalURL
			}
		}
	}

	return result
}

// connectWithNmcli connects using NetworkManager CLI.
func connectWithNmcli(ctx context.Context, iface, ssid, bssid, password string, timeout int) *ConnectionResult {
	log := svc1log.FromContext(ctx)
	result := NewConnectionResult()

	args := []string{"device", "wifi", "connect", ssid, "ifname", iface}
	if bssid != "" {
		args = append(args, "bssid", bssid)
	}
	if password != "" {
		args = append(args, "password", password)
	}

	log.Info("Connecting with nmcli", svc1log.SafeParam("ssid", ssid))

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "nmcli", args...)
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if err != nil {
		if timeoutCtx.Err() == context.DeadlineExceeded {
			result.WithTimeout("Connection timed out")
		} else if strings.Contains(outputStr, "No network with SSID") {
			result.WithError(associate.AssociationOutcomeNetworkNotFound, "Network not found")
		} else if strings.Contains(outputStr, "Secrets were required") ||
			strings.Contains(outputStr, "No secrets provided") ||
			strings.Contains(outputStr, "802-11-wireless-security.psk") {
			result.WithAuthFailed("Authentication failed - incorrect password")
		} else {
			result.WithError(associate.AssociationOutcomeAssocFailed, outputStr)
		}
		return result
	}

	// Verify connection
	time.Sleep(2 * time.Second)
	currentSSID, currentBSSID, connected := getCurrentConnection(ctx, iface)
	if connected && currentSSID == ssid {
		result.WithSuccess()

		// Get security info from nmcli
		negSec := getSecurityInfoNmcli(ctx, ssid)
		if negSec != nil {
			result.NegotiatedSecurity = negSec
		}
	} else {
		result.WithError(associate.AssociationOutcomeAssocFailed, "Connection not established after nmcli reported success")
	}

	// Store BSSID if available
	_ = currentBSSID

	return result
}

// connectWithNmcliEAP connects using NetworkManager CLI with EAP credentials.
func connectWithNmcliEAP(ctx context.Context, iface, ssid, identity, password string, timeout int) *ConnectionResult {
	log := svc1log.FromContext(ctx)
	result := NewConnectionResult()

	// Create a temporary connection profile for EAP
	connName := fmt.Sprintf("infrascan-test-%s", ssid)

	// Delete any existing test profile
	exec.Command("nmcli", "connection", "delete", connName).Run()

	// Create new connection with PEAP/MSCHAPv2 (most common for test identities)
	args := []string{
		"connection", "add",
		"type", "wifi",
		"con-name", connName,
		"ifname", iface,
		"ssid", ssid,
		"wifi-sec.key-mgmt", "wpa-eap",
		"802-1x.eap", "peap",
		"802-1x.phase2-auth", "mschapv2",
		"802-1x.identity", identity,
	}
	if password != "" {
		args = append(args, "802-1x.password", password)
	}

	log.Info("Creating EAP connection profile", svc1log.SafeParam("ssid", ssid))

	cmd := exec.Command("nmcli", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		result.WithError(associate.AssociationOutcomeDriverError, fmt.Sprintf("Failed to create EAP profile: %s", string(output)))
		return result
	}

	// Activate the connection
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd = exec.CommandContext(timeoutCtx, "nmcli", "connection", "up", connName)
	output, err = cmd.CombinedOutput()
	outputStr := string(output)

	// Clean up profile regardless of result
	defer exec.Command("nmcli", "connection", "delete", connName).Run()

	if err != nil {
		if timeoutCtx.Err() == context.DeadlineExceeded {
			result.WithTimeout("Connection timed out")
		} else if strings.Contains(outputStr, "No network with SSID") {
			result.WithError(associate.AssociationOutcomeNetworkNotFound, "Network not found")
		} else if strings.Contains(outputStr, "authentication") ||
			strings.Contains(outputStr, "Secrets were required") {
			result.WithAuthFailed("EAP authentication failed")
		} else {
			result.WithError(associate.AssociationOutcomeAssocFailed, outputStr)
		}
		return result
	}

	result.WithSuccess()

	// Set negotiated security
	negSec := &associate.NegotiatedSecurity{}
	eapMethod := associate.EapMethodPeap
	negSec.EapMethod = &eapMethod
	authMethod := common.AuthenticationMethodEap
	negSec.AuthenticationMethod = (*common.AuthenticationMethod)(&authMethod)
	result.NegotiatedSecurity = negSec
	result.EapMethodNegotiated = &eapMethod

	return result
}

// connectWithWpaSupplicant connects using wpa_supplicant directly.
func connectWithWpaSupplicant(ctx context.Context, iface, ssid, password string, timeout int) *ConnectionResult {
	result := NewConnectionResult()

	// Create temporary wpa_supplicant config
	configFile, err := os.CreateTemp("", "wpa_supplicant_*.conf")
	if err != nil {
		result.WithError(associate.AssociationOutcomeDriverError, fmt.Sprintf("Failed to create config: %v", err))
		return result
	}
	defer os.Remove(configFile.Name())

	var config string
	if password == "" {
		// Open network
		config = fmt.Sprintf(`network={
	ssid="%s"
	key_mgmt=NONE
}`, ssid)
	} else {
		// PSK network
		config = fmt.Sprintf(`network={
	ssid="%s"
	psk="%s"
	key_mgmt=WPA-PSK
}`, ssid, password)
	}

	if _, err := configFile.WriteString(config); err != nil {
		result.WithError(associate.AssociationOutcomeDriverError, fmt.Sprintf("Failed to write config: %v", err))
		return result
	}
	configFile.Close()

	// Run wpa_supplicant
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "wpa_supplicant", "-i", iface, "-c", configFile.Name(), "-B")
	if err := cmd.Run(); err != nil {
		result.WithError(associate.AssociationOutcomeDriverError, fmt.Sprintf("wpa_supplicant failed: %v", err))
		return result
	}

	// Wait for connection
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for time.Now().Before(deadline) {
		currentSSID, _, connected := getCurrentConnection(ctx, iface)
		if connected && currentSSID == ssid {
			result.WithSuccess()
			return result
		}
		time.Sleep(1 * time.Second)
	}

	result.WithTimeout("Connection timed out")
	return result
}

// getSecurityInfoNmcli retrieves negotiated security info using nmcli.
func getSecurityInfoNmcli(ctx context.Context, ssid string) *associate.NegotiatedSecurity {
	cmd := exec.Command("nmcli", "-t", "-f", "SECURITY", "device", "wifi", "list")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	// Parse security info
	negSec := &associate.NegotiatedSecurity{}

	outputStr := string(output)
	if strings.Contains(outputStr, "WPA3") {
		wpaVer := common.WpaVersionWpa3
		negSec.WpaVersion = (*common.WpaVersion)(&wpaVer)
		authMethod := common.AuthenticationMethodSae
		negSec.AuthenticationMethod = (*common.AuthenticationMethod)(&authMethod)
		pmf := true
		negSec.PmfNegotiated = &pmf
	} else if strings.Contains(outputStr, "WPA2") {
		wpaVer := common.WpaVersionWpa2
		negSec.WpaVersion = (*common.WpaVersion)(&wpaVer)
	} else if strings.Contains(outputStr, "WPA") {
		wpaVer := common.WpaVersionWpa1
		negSec.WpaVersion = (*common.WpaVersion)(&wpaVer)
	}

	return negSec
}

// waitForDHCPLinux waits for DHCP to assign an IP address on Linux.
func waitForDHCPLinux(ctx context.Context, iface string, timeout int) (acquired bool, ip string, gateway string, dns []string) {
	log := svc1log.FromContext(ctx)
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)

	for time.Now().Before(deadline) {
		// Get IP using ip addr
		cmd := exec.Command("ip", "-4", "addr", "show", iface)
		output, err := cmd.Output()
		if err == nil {
			ipRegex := regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+)`)
			if match := ipRegex.FindStringSubmatch(string(output)); len(match) > 1 {
				ip = match[1]
				if !strings.HasPrefix(ip, "169.254.") { // Not link-local
					// Get gateway
					cmd = exec.Command("ip", "route", "show", "default")
					output, _ = cmd.Output()
					gwRegex := regexp.MustCompile(`default via (\d+\.\d+\.\d+\.\d+)`)
					if match := gwRegex.FindStringSubmatch(string(output)); len(match) > 1 {
						gateway = match[1]
					}

					// Get DNS from resolv.conf
					dnsData, _ := os.ReadFile("/etc/resolv.conf")
					dnsRegex := regexp.MustCompile(`nameserver (\d+\.\d+\.\d+\.\d+)`)
					matches := dnsRegex.FindAllStringSubmatch(string(dnsData), -1)
					for _, m := range matches {
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

// detectCaptivePortalLinux checks for captive portal on Linux.
func detectCaptivePortalLinux(ctx context.Context) (detected bool, portalURL string) {
	log := svc1log.FromContext(ctx)

	// Use connectivity check URL
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Try common portal detection URLs
	urls := []string{
		"http://detectportal.firefox.com/success.txt",
		"http://connectivity-check.ubuntu.com/",
		"http://www.gstatic.com/generate_204",
	}

	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Redirect indicates captive portal
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
			location := resp.Header.Get("Location")
			return true, location
		}

		// Check response
		if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			// Firefox returns "success"
			if strings.Contains(string(body), "success") || len(body) == 0 {
				return false, ""
			}
			// Unexpected content might be a portal
			return true, ""
		}
	}

	log.Debug("Captive portal check completed - no portal detected")
	return false, ""
}

// checkCommandExists checks if a command is available.
func checkCommandExists(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

