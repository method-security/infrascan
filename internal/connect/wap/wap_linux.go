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

	"github.com/Method-Security/infrascan/generated/go/common"
	"github.com/Method-Security/infrascan/generated/go/connect"
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
	// Note: parts[2] is the CONNECTION profile name, which may differ from SSID
	cmd := exec.Command("nmcli", "-t", "-f", "DEVICE,STATE,CONNECTION", "device", "status")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 && parts[0] == iface && parts[1] == "connected" {
				connectionName := parts[2]
				// Get actual SSID from iw (more reliable than connection name)
				iwCmd := exec.Command("iw", "dev", iface, "link")
				iwOutput, iwErr := iwCmd.Output()
				if iwErr == nil {
					ssidRegex := regexp.MustCompile(`SSID: (.+)`)
					if match := ssidRegex.FindStringSubmatch(string(iwOutput)); len(match) > 1 {
						ssid = strings.TrimSpace(match[1])
					}
					bssidRegex := regexp.MustCompile(`Connected to ([0-9a-fA-F:]+)`)
					if match := bssidRegex.FindStringSubmatch(string(iwOutput)); len(match) > 1 {
						bssid = strings.ToUpper(match[1])
					}
				}
				// Fall back to connection name if iw didn't give SSID
				if ssid == "" {
					ssid = connectionName
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
				ssid = strings.TrimSpace(match[1])
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

// getConnectionProfileName returns the NetworkManager connection profile name for the active connection.
// This is used for restoring connections since 'nmcli connection up <profile>' is more reliable
// than 'nmcli device wifi connect <ssid>' which requires the network to be visible in a scan.
func getConnectionProfileName(ctx context.Context, interfaceName string) string {
	iface := interfaceName
	if iface == "" {
		var err error
		iface, err = findWirelessInterface(ctx)
		if err != nil {
			return ""
		}
	}

	// Get connection profile name from nmcli device status
	cmd := exec.Command("nmcli", "-t", "-f", "DEVICE,STATE,CONNECTION", "device", "status")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) >= 3 && parts[0] == iface && parts[1] == "connected" {
			return parts[2] // This is the connection profile name
		}
	}

	return ""
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
				_, _ = fmt.Sscanf(match[1], "%d", &rssi)
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
				_, _ = fmt.Sscanf(parts[1], "%d", &signal)
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
// Uses 'nmcli connection up' with the saved profile name, which is more reliable
// than 'nmcli device wifi connect' because it doesn't require the network to be
// visible in the current scan - it uses the saved connection profile.
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

	profileName := ""
	if original.ConnectionProfile != nil {
		profileName = *original.ConnectionProfile
	}

	if ssid == "" && profileName == "" {
		return fmt.Errorf("original network SSID and connection profile not available")
	}

	// Prefer using connection profile name with 'nmcli connection up'
	// This is more reliable because it uses the saved profile and doesn't
	// require the network to be visible in the current scan
	if profileName != "" {
		log.Info("Reconnecting to original network using saved profile",
			svc1log.SafeParam("profile", profileName),
			svc1log.SafeParam("ssid", ssid))

		cmd := exec.Command("nmcli", "connection", "up", profileName, "ifname", iface)
		output, err := cmd.CombinedOutput()
		if err == nil {
			// Wait and verify connection
			for i := 0; i < 10; i++ {
				time.Sleep(1 * time.Second)
				currentSSID, _, connected := getCurrentConnection(ctx, iface)
				if connected && (currentSSID == ssid || ssid == "") {
					return nil
				}
			}
			return fmt.Errorf("connection appeared to succeed but could not verify")
		}
		log.Warn("Failed to connect using profile, trying scan-based connect",
			svc1log.SafeParam("error", err.Error()),
			svc1log.SafeParam("output", string(output)))
	}

	// Fall back: Try to find and use an existing profile for this SSID
	// We avoid 'nmcli device wifi connect' because it creates a NEW profile each time,
	// leading to duplicates like "SSID", "SSID 1", "SSID 2", etc.
	if ssid != "" {
		log.Info("Looking for existing profile for SSID",
			svc1log.SafeParam("ssid", ssid))

		// Find existing connection profiles that match this SSID
		cmd := exec.Command("nmcli", "-t", "-f", "NAME,TYPE", "connection", "show")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 && parts[1] == "802-11-wireless" {
					existingProfile := parts[0]
					// Check if this profile is for our SSID
					ssidCmd := exec.Command("nmcli", "-t", "-f", "802-11-wireless.ssid", "connection", "show", existingProfile)
					ssidOutput, _ := ssidCmd.Output()
					if strings.TrimSpace(string(ssidOutput)) == "802-11-wireless.ssid:"+ssid {
						log.Info("Found existing profile for SSID, using it",
							svc1log.SafeParam("profile", existingProfile),
							svc1log.SafeParam("ssid", ssid))
						activateCmd := exec.Command("nmcli", "connection", "up", existingProfile, "ifname", iface)
						activateOutput, activateErr := activateCmd.CombinedOutput()
						if activateErr == nil {
							// Verify connection
							for i := 0; i < 10; i++ {
								time.Sleep(1 * time.Second)
								currentSSID, _, connected := getCurrentConnection(ctx, iface)
								if connected && currentSSID == ssid {
									return nil
								}
							}
						} else {
							log.Debug("Failed to activate existing profile",
								svc1log.SafeParam("profile", existingProfile),
								svc1log.SafeParam("error", activateErr.Error()),
								svc1log.SafeParam("output", string(activateOutput)))
						}
					}
				}
			}
		}
		return fmt.Errorf("could not find or activate existing profile for SSID: %s", ssid)
	}
	return fmt.Errorf("no SSID available for fallback connection")
}

// cleanupStaleTestProfiles removes any leftover infrascan-test-* connection profiles.
// These may be left behind if a previous run crashed or was interrupted.
func cleanupStaleTestProfiles(ctx context.Context) {
	log := svc1log.FromContext(ctx)

	cmd := exec.Command("nmcli", "-t", "-f", "NAME", "connection", "show")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		profileName := strings.TrimSpace(line)
		if strings.HasPrefix(profileName, "infrascan-test-") {
			log.Debug("Cleaning up stale test profile", svc1log.SafeParam("profile", profileName))
			_ = exec.Command("nmcli", "connection", "delete", profileName).Run()
		}
	}
}

// connectToNetwork performs the actual connection attempt on Linux.
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

	// Clean up any stale test profiles from previous runs
	cleanupStaleTestProfiles(ctx)

	iface := interfaceName
	if iface == "" {
		var err error
		iface, err = findWirelessInterface(ctx)
		if err != nil {
			result.WithError(connect.ConnectionOutcomeInterfaceError, err.Error())
			return result
		}
	}

	// Check if we have nmcli (NetworkManager)
	hasNmcli := checkCommandExists("nmcli")
	hasWpaSupplicant := checkCommandExists("wpa_supplicant")

	switch cred.CredentialType {
	case connect.TestCredentialTypeNone:
		// Open network connection
		if hasNmcli {
			result = connectWithNmcli(ctx, iface, targetSSID, targetBSSID, "", timeout)
		} else if hasWpaSupplicant {
			result = connectWithWpaSupplicant(ctx, iface, targetSSID, "", timeout, false)
		} else {
			result.WithError(connect.ConnectionOutcomeDriverError, "Neither nmcli nor wpa_supplicant available")
		}

	case connect.TestCredentialTypePskSimple, connect.TestCredentialTypePskCommon:
		// PSK connection
		if cred.Psk == nil || *cred.Psk == "" {
			result.WithError(connect.ConnectionOutcomeAuthFailed, "PSK credential required but not provided")
			return result
		}

		// If desktop popups are disallowed, do NOT use NetworkManager in a desktop session.
		// On GNOME/KDE, the NetworkManager "secret agent" will show an OS dialog after an auth
		// failure asking the user to re-enter the password. We can't reliably suppress that
		// from nmcli. The only deterministic way is to avoid NetworkManager for the attempt.
		inDesktopSession := os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
		if inDesktopSession && !allowDesktopPopups(ctx) {
			if os.Getuid() != 0 {
				result.WithError(
					connect.ConnectionOutcomePermissionDenied,
					"refusing to attempt WPA-Personal association via NetworkManager in a desktop session because authentication failures will trigger an OS password prompt. "+
						"Re-run with sudo to use the non-NetworkManager association path, or pass --allow-desktop-popups to allow the OS prompt.",
				)
				return result
			}
			if hasWpaSupplicant && hasNmcli {
				log.Info("Using non-NetworkManager association path to prevent desktop password prompts")
				result = connectWithWpaSupplicantNoNetworkManager(ctx, iface, targetSSID, *cred.Psk, timeout)
			} else if hasWpaSupplicant {
				// Best-effort fallback when nmcli isn't available to toggle managed state.
				result = connectWithWpaSupplicant(ctx, iface, targetSSID, *cred.Psk, timeout, false)
			} else {
				result.WithError(connect.ConnectionOutcomeDriverError, "wpa_supplicant not available (required to avoid NetworkManager desktop prompts)")
			}
			break
		}

		if hasNmcli {
			result = connectWithNmcli(ctx, iface, targetSSID, targetBSSID, *cred.Psk, timeout)
		} else if hasWpaSupplicant {
			result = connectWithWpaSupplicant(ctx, iface, targetSSID, *cred.Psk, timeout, false)
		} else {
			result.WithError(connect.ConnectionOutcomeDriverError, "Neither nmcli nor wpa_supplicant available")
		}

	case connect.TestCredentialTypeEapTestIdentity, connect.TestCredentialTypeEapGuest:
		// EAP connection
		if cred.EapIdentity == nil || *cred.EapIdentity == "" {
			result.WithError(connect.ConnectionOutcomeAuthFailed, "EAP identity required but not provided")
			return result
		}
		inDesktopSession := os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
		if inDesktopSession && !allowDesktopPopups(ctx) {
			// We currently use nmcli for EAP on Linux. That will trigger the desktop secret agent
			// on auth failures, so refuse unless explicitly allowed.
			result.WithError(
				connect.ConnectionOutcomePermissionDenied,
				"refusing to attempt WPA-Enterprise (EAP) association in a desktop session because authentication failures may trigger an OS password prompt. "+
					"Run from a non-desktop session or pass --allow-desktop-popups to allow the OS prompt.",
			)
			return result
		}
		if hasNmcli {
			result = connectWithNmcliEAP(ctx, iface, targetSSID, *cred.EapIdentity, ptrStr(cred.EapPassword), timeout)
		} else {
			log.Warn("EAP connection without nmcli is not supported")
			result.WithError(connect.ConnectionOutcomeDriverError, "EAP connection requires nmcli")
		}

	default:
		result.WithError(connect.ConnectionOutcomeUnknownError, fmt.Sprintf("unsupported credential type: %s", cred.CredentialType))
	}

	// If connection succeeded, get additional info (unless already done)
	// Note: connectWithWpaSupplicantNoNetworkManager does DHCP internally because it needs
	// to complete before restoring NetworkManager control. Other paths do DHCP here.
	if result.Outcome == connect.ConnectionOutcomeSuccess && result.IPAcquired == nil {
		// Get DHCP info
		ipAcquired, ip, gateway, dns := waitForDHCPLinux(ctx, iface, timeout)
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
			portalDetected, portalURL := detectCaptivePortalLinux(ctx)
			result.PortalDetected = &portalDetected
			if portalURL != "" {
				result.PortalURL = &portalURL
			}
		}
	}

	return result
}

// connectWithNmcli connects using NetworkManager CLI.
// This function is designed to be non-interactive - it will NOT prompt for credentials
// and will clean up any failed connection profiles to prevent desktop popups.
func connectWithNmcli(ctx context.Context, iface, ssid, bssid, password string, timeout int) *ConnectionResult {
	log := svc1log.FromContext(ctx)
	result := NewConnectionResult()

	// Use a unique connection name so we can clean it up later
	connName := fmt.Sprintf("infrascan-test-%s", ssid)

	// Delete any existing test profile first to ensure clean state
	_ = exec.Command("nmcli", "connection", "delete", connName).Run()

	// Build connection arguments
	// We create a temporary connection profile rather than using "wifi connect"
	// because this gives us more control and prevents the secret agent from prompting.
	//
	// CRITICAL: We set wifi-sec.psk-flags=0 to tell NetworkManager:
	//   0 = NONE - the secret is stored in the connection profile itself
	// This prevents NetworkManager from consulting the secret agent (which causes desktop popups).
	// Without this flag, even failed auth attempts can trigger the gnome-keyring or KDE wallet popup.
	var args []string
	if password != "" {
		// PSK network - embed password directly, no secret agent
		args = []string{
			"connection", "add",
			"type", "wifi",
			"con-name", connName,
			"ifname", iface,
			"ssid", ssid,
			"wifi-sec.key-mgmt", "wpa-psk",
			"wifi-sec.psk", password,
			"wifi-sec.psk-flags", "0", // Store in profile, don't use secret agent
			"connection.autoconnect", "no", // Don't auto-retry on failure
		}
	} else {
		// Open network (no security)
		args = []string{
			"connection", "add",
			"type", "wifi",
			"con-name", connName,
			"ifname", iface,
			"ssid", ssid,
			"connection.autoconnect", "no", // Don't auto-retry on failure
		}
	}

	log.Info("Creating temporary connection profile", svc1log.SafeParam("ssid", ssid))

	// Create the connection profile
	createCmd := exec.Command("nmcli", args...)
	createOutput, err := createCmd.CombinedOutput()
	if err != nil {
		log.Warn("Failed to create connection profile",
			svc1log.SafeParam("output", string(createOutput)),
			svc1log.SafeParam("error", err.Error()))
		result.WithError(connect.ConnectionOutcomeDriverError, fmt.Sprintf("Failed to create connection profile: %s", string(createOutput)))
		return result
	}

	// Track whether we should keep the profile (for --test-only=false with successful connection)
	keepProfile := false

	// Ensure we clean up the connection profile when done, unless we want to stay connected
	defer func() {
		if keepProfile {
			// Rename the temp profile to the SSID for user-friendliness
			log.Debug("Renaming test profile to permanent profile", svc1log.SafeParam("old", connName), svc1log.SafeParam("new", ssid))
			// First check if a profile with SSID name already exists
			_ = exec.Command("nmcli", "connection", "delete", ssid).Run()
			// Rename our test profile to the SSID
			if err := exec.Command("nmcli", "connection", "modify", connName, "connection.id", ssid).Run(); err != nil {
				log.Warn("Failed to rename profile, keeping test name", svc1log.SafeParam("error", err.Error()))
			}
			log.Info("Connection profile saved for persistence", svc1log.SafeParam("profile", ssid))
		} else {
			log.Debug("Cleaning up test connection profile", svc1log.SafeParam("conn_name", connName))
			_ = exec.Command("nmcli", "connection", "delete", connName).Run()
		}
	}()

	// Now activate the connection
	log.Info("Activating connection", svc1log.SafeParam("ssid", ssid))

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// Use "connection up" with --wait to control timeout, no interactive prompts
	upArgs := []string{"--wait", fmt.Sprintf("%d", timeout), "connection", "up", connName}
	cmd := exec.CommandContext(timeoutCtx, "nmcli", upArgs...)

	// Ensure no stdin to prevent any interactive prompts
	cmd.Stdin = nil

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if err != nil {
		if timeoutCtx.Err() == context.DeadlineExceeded {
			result.WithTimeout("Connection timed out")
		} else if strings.Contains(outputStr, "No network with SSID") ||
			strings.Contains(outputStr, "not found") {
			result.WithError(connect.ConnectionOutcomeNetworkNotFound, "Network not found")
		} else if strings.Contains(outputStr, "Secrets were required") ||
			strings.Contains(outputStr, "No secrets provided") ||
			strings.Contains(outputStr, "802-11-wireless-security.psk") ||
			strings.Contains(outputStr, "psk-flags") ||
			strings.Contains(outputStr, "secrets:") ||
			strings.Contains(outputStr, "authentication") {
			result.WithAuthFailed("Authentication failed - incorrect password")
		} else {
			result.WithError(connect.ConnectionOutcomeAssocFailed, outputStr)
		}
		return result
	}

	// Verify connection
	time.Sleep(2 * time.Second)
	currentSSID, currentBSSID, connected := getCurrentConnection(ctx, iface)
	if connected && currentSSID == ssid {
		result.WithSuccess()

		// Store the actual connected BSSID
		if currentBSSID != "" {
			result.ConnectedBSSID = &currentBSSID
			log.Debug("Connected to BSSID", svc1log.SafeParam("bssid", currentBSSID))
		}

		// Get security info from nmcli
		negSec := getSecurityInfoNmcli(ctx, ssid)
		if negSec != nil {
			result.NegotiatedSecurity = negSec
		}

		// If --test-only=false, keep the profile for persistence
		if !isTestOnly(ctx) {
			keepProfile = true
			log.Info("Marking profile for persistence (--test-only=false)")
		}
	} else {
		result.WithError(connect.ConnectionOutcomeAssocFailed, "Connection not established after nmcli reported success")
	}

	return result
}

// connectWithNmcliEAP connects using NetworkManager CLI with EAP credentials.
// This function is designed to be non-interactive - it will NOT prompt for credentials
// and will clean up any failed connection profiles to prevent desktop popups.
func connectWithNmcliEAP(ctx context.Context, iface, ssid, identity, password string, timeout int) *ConnectionResult {
	log := svc1log.FromContext(ctx)
	result := NewConnectionResult()

	// Create a temporary connection profile for EAP
	connName := fmt.Sprintf("infrascan-test-%s", ssid)

	// Delete any existing test profile first to ensure clean state
	_ = exec.Command("nmcli", "connection", "delete", connName).Run()

	// Create new connection with PEAP/MSCHAPv2 (most common for test identities)
	// CRITICAL: We set 802-1x.password-flags=0 to tell NetworkManager:
	//   0 = NONE - the secret is stored in the connection profile itself
	// This prevents NetworkManager from consulting the secret agent (which causes desktop popups).
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
		"802-1x.password-flags", "0", // Store in profile, don't use secret agent
	}
	if password != "" {
		args = append(args, "802-1x.password", password)
	}

	log.Info("Creating EAP connection profile", svc1log.SafeParam("ssid", ssid))

	createCmd := exec.Command("nmcli", args...)
	output, err := createCmd.CombinedOutput()
	if err != nil {
		result.WithError(connect.ConnectionOutcomeDriverError, fmt.Sprintf("Failed to create EAP profile: %s", string(output)))
		return result
	}

	// Track whether we should keep the profile (for --test-only=false with successful connection)
	keepProfile := false

	// Ensure we clean up the connection profile when done, unless we want to stay connected
	defer func() {
		if keepProfile {
			// Rename the temp profile to the SSID for user-friendliness
			log.Debug("Renaming test EAP profile to permanent profile", svc1log.SafeParam("old", connName), svc1log.SafeParam("new", ssid))
			_ = exec.Command("nmcli", "connection", "delete", ssid).Run()
			if err := exec.Command("nmcli", "connection", "modify", connName, "connection.id", ssid).Run(); err != nil {
				log.Warn("Failed to rename EAP profile, keeping test name", svc1log.SafeParam("error", err.Error()))
			}
			log.Info("EAP connection profile saved for persistence", svc1log.SafeParam("profile", ssid))
		} else {
			log.Debug("Cleaning up test EAP connection profile", svc1log.SafeParam("conn_name", connName))
			_ = exec.Command("nmcli", "connection", "delete", connName).Run()
		}
	}()

	// Activate the connection with --wait to control timeout, no interactive prompts
	log.Info("Activating EAP connection", svc1log.SafeParam("ssid", ssid))

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	upArgs := []string{"--wait", fmt.Sprintf("%d", timeout), "connection", "up", connName}
	cmd := exec.CommandContext(timeoutCtx, "nmcli", upArgs...)

	// Ensure no stdin to prevent any interactive prompts
	cmd.Stdin = nil

	output, err = cmd.CombinedOutput()
	outputStr := string(output)

	if err != nil {
		if timeoutCtx.Err() == context.DeadlineExceeded {
			result.WithTimeout("Connection timed out")
		} else if strings.Contains(outputStr, "No network with SSID") ||
			strings.Contains(outputStr, "not found") {
			result.WithError(connect.ConnectionOutcomeNetworkNotFound, "Network not found")
		} else if strings.Contains(outputStr, "authentication") ||
			strings.Contains(outputStr, "Secrets were required") ||
			strings.Contains(outputStr, "secrets:") ||
			strings.Contains(outputStr, "802-1x") {
			result.WithAuthFailed("EAP authentication failed - incorrect identity or password")
		} else {
			result.WithError(connect.ConnectionOutcomeAssocFailed, outputStr)
		}
		return result
	}

	result.WithSuccess()

	// Get the actual connected BSSID
	_, currentBSSID, _ := getCurrentConnection(ctx, iface)
	if currentBSSID != "" {
		result.ConnectedBSSID = &currentBSSID
		log.Debug("Connected to BSSID", svc1log.SafeParam("bssid", currentBSSID))
	}

	// Set negotiated security
	negSec := &connect.NegotiatedSecurity{}
	eapMethod := connect.EapMethodPeap
	negSec.EapMethod = &eapMethod
	authMethod := common.AuthenticationMethodEap
	negSec.AuthenticationMethod = &authMethod
	result.NegotiatedSecurity = negSec
	result.EapMethodNegotiated = &eapMethod

	// If --test-only=false, keep the profile for persistence
	if !isTestOnly(ctx) {
		keepProfile = true
		log.Info("Marking EAP profile for persistence (--test-only=false)")
	}

	return result
}

// handoffToNetworkManager creates a persistent NetworkManager connection profile and activates it.
// This is used when --test-only=false to ensure the connection survives after wpa_supplicant exits.
// The function creates a new connection profile (or reuses existing) and activates it.
func handoffToNetworkManager(ctx context.Context, iface, ssid, password string) error {
	log := svc1log.FromContext(ctx)

	// First, make sure the interface is managed by NetworkManager
	// (we may have marked it unmanaged earlier)
	_ = exec.Command("nmcli", "device", "set", iface, "managed", "yes").Run()
	time.Sleep(500 * time.Millisecond)

	// Check if there's already a connection profile for this SSID
	existingProfile := ""
	cmd := exec.Command("nmcli", "-t", "-f", "NAME,TYPE", "connection", "show")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 && parts[1] == "802-11-wireless" {
				profileName := parts[0]
				// Check if this profile is for our SSID
				ssidCmd := exec.Command("nmcli", "-t", "-f", "802-11-wireless.ssid", "connection", "show", profileName)
				ssidOutput, _ := ssidCmd.Output()
				if strings.TrimSpace(string(ssidOutput)) == "802-11-wireless.ssid:"+ssid {
					existingProfile = profileName
					log.Debug("Found existing NetworkManager profile for SSID",
						svc1log.SafeParam("profile", existingProfile),
						svc1log.SafeParam("ssid", ssid))
					break
				}
			}
		}
	}

	if existingProfile != "" {
		// Update password in existing profile and activate
		if password != "" {
			_ = exec.Command("nmcli", "connection", "modify", existingProfile,
				"wifi-sec.key-mgmt", "wpa-psk",
				"wifi-sec.psk", password).Run()
		}
		log.Info("Activating existing NetworkManager profile", svc1log.SafeParam("profile", existingProfile))
		cmd = exec.Command("nmcli", "connection", "up", existingProfile, "ifname", iface)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to activate existing profile: %s - %w", string(output), err)
		}
	} else {
		// Create a new persistent connection profile
		connName := ssid // Use SSID as profile name for user-friendliness
		log.Info("Creating new NetworkManager profile", svc1log.SafeParam("profile", connName))

		var args []string
		if password != "" {
			args = []string{
				"connection", "add",
				"type", "wifi",
				"con-name", connName,
				"ssid", ssid,
				"wifi-sec.key-mgmt", "wpa-psk",
				"wifi-sec.psk", password,
				"connection.autoconnect", "yes",
				"ifname", iface,
			}
		} else {
			args = []string{
				"connection", "add",
				"type", "wifi",
				"con-name", connName,
				"ssid", ssid,
				"connection.autoconnect", "yes",
				"ifname", iface,
			}
		}

		cmd = exec.Command("nmcli", args...)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to create profile: %s - %w", string(output), err)
		}

		// Activate the new profile
		cmd = exec.Command("nmcli", "connection", "up", connName, "ifname", iface)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to activate new profile: %s - %w", string(output), err)
		}
	}

	// Wait a moment for NetworkManager to fully take over
	time.Sleep(1 * time.Second)

	// Verify we're still connected
	currentSSID, _, connected := getCurrentConnection(ctx, iface)
	if !connected || currentSSID != ssid {
		return fmt.Errorf("NetworkManager did not maintain connection (current: %s, expected: %s)", currentSSID, ssid)
	}

	log.Info("NetworkManager has taken over the connection", svc1log.SafeParam("ssid", ssid))
	return nil
}

// connectWithWpaSupplicantNoNetworkManager temporarily marks the interface unmanaged by NetworkManager
// and attempts association using wpa_supplicant. This prevents NetworkManager (and its desktop secret
// agents) from showing password prompt dialogs on auth failures.
//
// IMPORTANT: This requires root privileges.
// IMPORTANT: This function also handles DHCP while the device is unmanaged, because
// once we restore managed state, NetworkManager will interfere with our connection.
func connectWithWpaSupplicantNoNetworkManager(ctx context.Context, iface, ssid, password string, timeout int) *ConnectionResult {
	log := svc1log.FromContext(ctx)
	result := NewConnectionResult()

	if os.Getuid() != 0 {
		result.WithError(connect.ConnectionOutcomePermissionDenied, "root privileges required for non-NetworkManager association path")
		return result
	}

	// Best-effort: disconnect and mark unmanaged so NM won't interfere / trigger UI.
	_ = exec.Command("nmcli", "device", "disconnect", iface).Run()
	if out, err := exec.Command("nmcli", "device", "set", iface, "managed", "no").CombinedOutput(); err != nil {
		result.WithError(connect.ConnectionOutcomeDriverError, fmt.Sprintf("failed to set device unmanaged (nmcli device set %s managed no): %s", iface, strings.TrimSpace(string(out))))
		return result
	}
	defer func() {
		// Restore managed state - AFTER we've done DHCP
		if out, err := exec.Command("nmcli", "device", "set", iface, "managed", "yes").CombinedOutput(); err != nil {
			log.Warn("Failed to restore device to managed=yes",
				svc1log.SafeParam("iface", iface),
				svc1log.SafeParam("output", strings.TrimSpace(string(out))),
				svc1log.SafeParam("error", err.Error()))
		}
	}()

	// Connect using wpa_supplicant with DHCP enabled
	// IMPORTANT: doDHCP=true because DHCP must happen while wpa_supplicant is still running.
	// wpa_supplicant is killed when connectWithWpaSupplicant returns (defer), and without it
	// the WiFi connection dies and DHCP fails with "no carrier".
	return connectWithWpaSupplicant(ctx, iface, ssid, password, timeout, true)
}

// connectWithWpaSupplicant connects using wpa_supplicant directly.
// It properly detects authentication failures by monitoring wpa_supplicant output
// and using wpa_cli to check connection status.
//
// IMPORTANT: This function also handles DHCP and platform connectivity testing if enabled.
// This is necessary because wpa_supplicant must remain running for the WiFi connection
// to stay up. If we return and let the defer kill wpa_supplicant, the connection dies.
//
// Parameters:
//   - doDHCP: if true, acquire DHCP after successful connection. If DHCP is acquired
//     and a platform URL is configured via context, platform connectivity is also tested.
func connectWithWpaSupplicant(ctx context.Context, iface, ssid, password string, timeout int, doDHCP bool) *ConnectionResult {
	log := svc1log.FromContext(ctx)
	result := NewConnectionResult()

	// Kill any existing wpa_supplicant on this interface
	_ = exec.Command("pkill", "-f", fmt.Sprintf("wpa_supplicant.*-i.*%s", iface)).Run()
	time.Sleep(500 * time.Millisecond)

	// CRITICAL: Bring interface DOWN then UP to clear any existing connection state.
	// Without this, `iw dev link` might report an old connection that existed before we started.
	log.Debug("Clearing existing connection state", svc1log.SafeParam("iface", iface))
	_ = exec.Command("ip", "link", "set", iface, "down").Run()
	time.Sleep(500 * time.Millisecond)
	_ = exec.Command("ip", "link", "set", iface, "up").Run()
	time.Sleep(500 * time.Millisecond)

	// Verify we're disconnected
	iwCheck := exec.Command("iw", "dev", iface, "link")
	iwOut, _ := iwCheck.CombinedOutput()
	if !strings.Contains(string(iwOut), "Not connected") {
		log.Debug("Interface still shows connected after reset, forcing disconnect")
		// Try harder to disconnect
		_ = exec.Command("iw", "dev", iface, "disconnect").Run()
		time.Sleep(1 * time.Second)
	}

	// Create temporary wpa_supplicant config with ctrl_interface for wpa_cli
	configFile, err := os.CreateTemp("", "wpa_supplicant_*.conf")
	if err != nil {
		result.WithError(connect.ConnectionOutcomeDriverError, fmt.Sprintf("Failed to create config: %v", err))
		return result
	}
	defer func() { _ = os.Remove(configFile.Name()) }()

	ctrlInterface := fmt.Sprintf("/tmp/wpa_supplicant_%s", iface)

	var config string
	if password == "" {
		// Open network
		config = fmt.Sprintf(`ctrl_interface=%s
network={
	ssid="%s"
	key_mgmt=NONE
}`, ctrlInterface, ssid)
	} else {
		// PSK network
		config = fmt.Sprintf(`ctrl_interface=%s
network={
	ssid="%s"
	psk="%s"
	key_mgmt=WPA-PSK
}`, ctrlInterface, ssid, password)
	}

	if _, err := configFile.WriteString(config); err != nil {
		result.WithError(connect.ConnectionOutcomeDriverError, fmt.Sprintf("Failed to write config: %v", err))
		return result
	}
	_ = configFile.Close()

	// Run wpa_supplicant in background but capture initial output
	log.Debug("Starting wpa_supplicant", svc1log.SafeParam("iface", iface), svc1log.SafeParam("ssid", ssid))
	cmd := exec.Command("wpa_supplicant", "-i", iface, "-c", configFile.Name(), "-B", "-d")
	output, err := cmd.CombinedOutput()
	if err != nil {
		result.WithError(connect.ConnectionOutcomeDriverError, fmt.Sprintf("wpa_supplicant failed to start: %v - %s", err, string(output)))
		return result
	}

	// Ensure we kill wpa_supplicant when done
	defer func() {
		_ = exec.Command("pkill", "-f", fmt.Sprintf("wpa_supplicant.*-i.*%s", iface)).Run()
		// Clean up ctrl interface
		_ = os.RemoveAll(ctrlInterface)
	}()

	// Wait for wpa_supplicant to initialize
	time.Sleep(1 * time.Second)

	// Set up attempted security info (what we're TRYING to negotiate)
	attemptedSec := &connect.NegotiatedSecurity{}
	if password != "" {
		wpaVer := common.WpaVersionWpa2 // Assume WPA2 for PSK
		attemptedSec.WpaVersion = &wpaVer
		authMethod := common.AuthenticationMethodPsk
		attemptedSec.AuthenticationMethod = &authMethod
		cipher := common.CipherSuiteCcmp128
		attemptedSec.PairwiseCipher = &cipher
	}
	result.AttemptedSecurity = attemptedSec

	// Initialize timing tracking
	timing := &connect.ConnectionTiming{}
	overallStart := time.Now()
	var associationStart, handshakeStart time.Time

	// Poll wpa_cli for connection status
	// For PSK networks, the 4-way handshake should complete within 15-20 seconds
	// if the password is correct. Longer than that almost always means wrong password.
	handshakeTimeout := 20 * time.Second
	if password == "" {
		// Open networks can take longer (just association, no 4-way handshake)
		handshakeTimeout = time.Duration(timeout) * time.Second
	}

	deadline := overallStart.Add(handshakeTimeout)
	disconnectCount := 0
	retryCount := 0

	// Track the highest handshake progress we've seen
	var highestProgress connect.HandshakeProgress = connect.HandshakeProgressNotStarted
	result.HandshakeProgress = &highestProgress

	for time.Now().Before(deadline) {
		// Check wpa_cli status - this is the ONLY reliable source of truth
		statusCmd := exec.Command("wpa_cli", "-i", iface, "-p", ctrlInterface, "status")
		statusOutput, err := statusCmd.CombinedOutput()
		statusStr := string(statusOutput)

		if err == nil {
			// Extract wpa_state for logging
			stateMatch := regexp.MustCompile(`(?m)^wpa_state=(.+)$`).FindStringSubmatch(statusStr)
			currentState := "unknown"
			if len(stateMatch) > 1 {
				currentState = stateMatch[1]
			}
			log.Debug("wpa_cli status", svc1log.SafeParam("wpa_state", currentState))

			// Map wpa_state to HandshakeProgress and track timing
			newProgress := mapWpaStateToProgress(currentState)
			if progressOrder(newProgress) > progressOrder(highestProgress) {
				highestProgress = newProgress
				result.HandshakeProgress = &highestProgress

				// Record timing milestones
				now := time.Now()
				switch newProgress {
				case connect.HandshakeProgressAssociating:
					if associationStart.IsZero() {
						associationStart = now
					}
				case connect.HandshakeProgressAssociated:
					if !associationStart.IsZero() {
						dur := int(now.Sub(associationStart).Milliseconds())
						timing.AssociationDurationMs = &dur
					}
				case connect.HandshakeProgressFourWayMsg1Received:
					if handshakeStart.IsZero() {
						handshakeStart = now
					}
				}
			}

			// Check for successful connection - ONLY trust wpa_state=COMPLETED
			if strings.Contains(statusStr, "wpa_state=COMPLETED") {
				// Verify SSID matches
				ssidMatch := regexp.MustCompile(`(?m)^ssid=(.+)$`).FindStringSubmatch(statusStr)
				if len(ssidMatch) > 1 && ssidMatch[1] == ssid {
					log.Info("wpa_supplicant connected successfully (wpa_state=COMPLETED)")

					// Wait for kernel to fully establish the link
					// wpa_supplicant reports COMPLETED but kernel may need a moment
					log.Debug("Waiting for kernel link to stabilize")
					time.Sleep(2 * time.Second)

					// Verify with iw that we're actually connected at kernel level
					iwCmd := exec.Command("iw", "dev", iface, "link")
					iwOut, _ := iwCmd.CombinedOutput()
					iwOutStr := string(iwOut)
					if strings.Contains(iwOutStr, "Not connected") {
						log.Warn("wpa_supplicant says COMPLETED but iw shows not connected, waiting more")
						time.Sleep(3 * time.Second)
					} else {
						log.Debug("Kernel link verified", svc1log.SafeParam("iw_output", iwOutStr))
					}

					// Record final timing
					now := time.Now()
					if !handshakeStart.IsZero() {
						dur := int(now.Sub(handshakeStart).Milliseconds())
						timing.HandshakeDurationMs = &dur
					}
					totalDur := int(now.Sub(overallStart).Milliseconds())
					timing.TotalDurationMs = &totalDur
					result.Timing = timing

					highestProgress = connect.HandshakeProgressCompleted
					result.HandshakeProgress = &highestProgress

					// Parse negotiated security from wpa_cli status
					result.NegotiatedSecurity = parseNegotiatedSecurityFromWpaCli(statusStr)

					// Parse BSSID from wpa_cli status
					if bssidMatch := regexp.MustCompile(`(?m)^bssid=([0-9a-fA-F:]+)$`).FindStringSubmatch(statusStr); len(bssidMatch) > 1 {
						connectedBSSID := strings.ToUpper(bssidMatch[1])
						result.ConnectedBSSID = &connectedBSSID
						log.Debug("Connected to BSSID (from wpa_cli)", svc1log.SafeParam("bssid", connectedBSSID))
					}

					result.WithSuccess()

					// If doDHCP is true, acquire DHCP NOW while wpa_supplicant is still running
					// This is critical: wpa_supplicant keeps the WiFi connection alive.
					// If we return first, the defer kills wpa_supplicant and connection dies.
					if doDHCP {
						log.Info("Acquiring DHCP lease while wpa_supplicant is running")
						ipAcquired, ip, gateway, dns := waitForDHCPLinux(ctx, iface, timeout)
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
							portalDetected, portalURL := detectCaptivePortalLinux(ctx)
							result.PortalDetected = &portalDetected
							if portalURL != "" {
								result.PortalURL = &portalURL
							}

							// Test platform connectivity if URL is provided via context
							// This MUST happen while still connected (wpa_supplicant running)
							platformURL := getPlatformURL(ctx)
							if platformURL != "" {
								log.Info("Testing platform connectivity while connected",
									svc1log.SafeParam("url", platformURL))
								result.PlatformConnectivity = testPlatformConnectivity(ctx, &platformURL)
							}

							// If --test-only=false, hand off to NetworkManager before we exit
							// This creates a persistent connection profile that survives wpa_supplicant exit
							if !isTestOnly(ctx) {
								log.Info("Handing off connection to NetworkManager for persistence (--test-only=false)")
								if err := handoffToNetworkManager(ctx, iface, ssid, password); err != nil {
									log.Warn("Failed to hand off to NetworkManager, connection will be lost when command exits",
										svc1log.SafeParam("error", err.Error()))
								} else {
									log.Info("Successfully handed off to NetworkManager, connection will persist")
								}
							}
						}
					}

					return result
				}
			}

			// Count disconnects - multiple disconnects after associating = auth failure
			if strings.Contains(statusStr, "wpa_state=DISCONNECTED") {
				if progressOrder(highestProgress) >= progressOrder(connect.HandshakeProgressAssociating) {
					disconnectCount++
					retryCount++
					log.Debug("Disconnect detected after associating",
						svc1log.SafeParam("count", disconnectCount),
						svc1log.SafeParam("highest_progress", highestProgress))

					// Multiple disconnects after we saw associating = wrong password
					if disconnectCount >= 2 {
						log.Info("Multiple disconnects after association - auth failure")

						// Record timing and progress
						now := time.Now()
						totalDur := int(now.Sub(overallStart).Milliseconds())
						timing.TotalDurationMs = &totalDur
						result.Timing = timing
						result.RetryCount = &retryCount

						// Set reason code - 4-way handshake timeout is reason 15
						if progressOrder(highestProgress) >= progressOrder(connect.HandshakeProgressFourWayMsg1Received) {
							reasonCode := connect.DeauthReasonCodeFourWayHandshakeTimeout
							result.DeauthReasonCode = &reasonCode
							rawCode := 15
							result.DeauthReasonCodeRaw = &rawCode
						}

						result.WithAuthFailed("Authentication failed - incorrect password")
						return result
					}
				}
			}
		} else {
			log.Debug("wpa_cli status failed", svc1log.SafeParam("error", err.Error()))
		}

		time.Sleep(1 * time.Second)
	}

	// Timeout reached - record final timing
	now := time.Now()
	totalDur := int(now.Sub(overallStart).Milliseconds())
	timing.TotalDurationMs = &totalDur
	result.Timing = timing
	result.RetryCount = &retryCount

	if password != "" {
		// For PSK networks, timeout after we tried to associate = wrong password
		if progressOrder(highestProgress) >= progressOrder(connect.HandshakeProgressAssociating) {
			// Set reason code based on how far we got
			if progressOrder(highestProgress) >= progressOrder(connect.HandshakeProgressFourWayMsg1Received) {
				reasonCode := connect.DeauthReasonCodeFourWayHandshakeTimeout
				result.DeauthReasonCode = &reasonCode
				rawCode := 15
				result.DeauthReasonCodeRaw = &rawCode
				result.WithAuthFailed("Authentication failed - 4-way handshake did not complete (wrong password)")
			} else {
				result.WithAuthFailed("Authentication failed - association rejected (wrong password or AP rejected)")
			}
		} else {
			result.WithAuthFailed("Authentication failed - could not associate with network (wrong password or network not in range)")
		}
	} else {
		result.WithTimeout("Connection timed out")
	}
	return result
}

// mapWpaStateToProgress maps wpa_supplicant state strings to HandshakeProgress enum.
func mapWpaStateToProgress(state string) connect.HandshakeProgress {
	switch strings.ToUpper(state) {
	case "DISCONNECTED", "INACTIVE":
		return connect.HandshakeProgressDisconnected
	case "SCANNING":
		return connect.HandshakeProgressScanning
	case "AUTHENTICATING":
		return connect.HandshakeProgressAuthenticating
	case "ASSOCIATING":
		return connect.HandshakeProgressAssociating
	case "ASSOCIATED":
		return connect.HandshakeProgressAssociated
	case "4WAY_HANDSHAKE":
		// We're in the 4-way handshake but don't know exact message
		return connect.HandshakeProgressFourWayMsg1Received
	case "GROUP_HANDSHAKE":
		return connect.HandshakeProgressGroupHandshake
	case "COMPLETED":
		return connect.HandshakeProgressCompleted
	default:
		return connect.HandshakeProgressNotStarted
	}
}

// progressOrder returns a numeric order for HandshakeProgress for comparison.
func progressOrder(p connect.HandshakeProgress) int {
	switch p {
	case connect.HandshakeProgressNotStarted:
		return 0
	case connect.HandshakeProgressScanning:
		return 1
	case connect.HandshakeProgressAuthenticating:
		return 2
	case connect.HandshakeProgressAssociating:
		return 3
	case connect.HandshakeProgressAssociated:
		return 4
	case connect.HandshakeProgressFourWayMsg1Received:
		return 5
	case connect.HandshakeProgressFourWayMsg2Sent:
		return 6
	case connect.HandshakeProgressFourWayMsg3Received:
		return 7
	case connect.HandshakeProgressFourWayMsg4Sent:
		return 8
	case connect.HandshakeProgressGroupHandshake:
		return 9
	case connect.HandshakeProgressCompleted:
		return 10
	case connect.HandshakeProgressDisconnected:
		return -1 // Special case
	default:
		return 0
	}
}

// parseNegotiatedSecurityFromWpaCli parses security info from wpa_cli status output.
func parseNegotiatedSecurityFromWpaCli(statusStr string) *connect.NegotiatedSecurity {
	negSec := &connect.NegotiatedSecurity{}

	// Parse key_mgmt
	if keyMgmt := regexp.MustCompile(`(?m)^key_mgmt=(.+)$`).FindStringSubmatch(statusStr); len(keyMgmt) > 1 {
		switch strings.ToUpper(keyMgmt[1]) {
		case "WPA2-PSK":
			wpaVer := common.WpaVersionWpa2
			negSec.WpaVersion = &wpaVer
			authMethod := common.AuthenticationMethodPsk
			negSec.AuthenticationMethod = &authMethod
		case "WPA-PSK":
			wpaVer := common.WpaVersionWpa1
			negSec.WpaVersion = &wpaVer
			authMethod := common.AuthenticationMethodPsk
			negSec.AuthenticationMethod = &authMethod
		case "SAE":
			wpaVer := common.WpaVersionWpa3
			negSec.WpaVersion = &wpaVer
			authMethod := common.AuthenticationMethodSae
			negSec.AuthenticationMethod = &authMethod
			pmf := true
			negSec.PmfNegotiated = &pmf
		}
	}

	// Parse pairwise_cipher
	if pairwise := regexp.MustCompile(`(?m)^pairwise_cipher=(.+)$`).FindStringSubmatch(statusStr); len(pairwise) > 1 {
		switch strings.ToUpper(pairwise[1]) {
		case "CCMP":
			cipher := common.CipherSuiteCcmp128
			negSec.PairwiseCipher = &cipher
		case "GCMP":
			cipher := common.CipherSuiteGcmp128
			negSec.PairwiseCipher = &cipher
		case "TKIP":
			cipher := common.CipherSuiteTkip
			negSec.PairwiseCipher = &cipher
		}
	}

	// Parse group_cipher
	if group := regexp.MustCompile(`(?m)^group_cipher=(.+)$`).FindStringSubmatch(statusStr); len(group) > 1 {
		switch strings.ToUpper(group[1]) {
		case "CCMP":
			cipher := common.CipherSuiteCcmp128
			negSec.GroupCipher = &cipher
		case "GCMP":
			cipher := common.CipherSuiteGcmp128
			negSec.GroupCipher = &cipher
		case "TKIP":
			cipher := common.CipherSuiteTkip
			negSec.GroupCipher = &cipher
		}
	}

	return negSec
}

// getSecurityInfoNmcli retrieves negotiated security info using nmcli.
func getSecurityInfoNmcli(ctx context.Context, ssid string) *connect.NegotiatedSecurity {
	cmd := exec.Command("nmcli", "-t", "-f", "SECURITY", "device", "wifi", "list")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	// Parse security info
	negSec := &connect.NegotiatedSecurity{}

	outputStr := string(output)
	if strings.Contains(outputStr, "WPA3") {
		wpaVer := common.WpaVersionWpa3
		negSec.WpaVersion = &wpaVer
		authMethod := common.AuthenticationMethodSae
		negSec.AuthenticationMethod = &authMethod
		pmf := true
		negSec.PmfNegotiated = &pmf
	} else if strings.Contains(outputStr, "WPA2") {
		wpaVer := common.WpaVersionWpa2
		negSec.WpaVersion = &wpaVer
	} else if strings.Contains(outputStr, "WPA") {
		wpaVer := common.WpaVersionWpa1
		negSec.WpaVersion = &wpaVer
	}

	return negSec
}

// triggerDHCP starts a DHCP client on the interface.
// This is necessary when using wpa_supplicant directly (non-NetworkManager path)
// because wpa_supplicant only handles 802.11 authentication, not DHCP.
func triggerDHCP(ctx context.Context, iface string) error {
	log := svc1log.FromContext(ctx)

	// Note: We skip carrier detection because for wireless interfaces, the kernel
	// carrier/operstate files may not accurately reflect connection status after
	// wpa_supplicant connects. dhcpcd has its own carrier wait logic (-w flag
	// or internal timeout) that works better for wireless.

	// DHCP client paths - try both PATH and common absolute locations
	// since /usr/sbin may not be in PATH for some sudo configurations
	dhcpClients := []struct {
		name string
		args []string
	}{
		// dhcpcd - common on Arch, Gentoo, some Ubuntu versions
		// Flags: -4 (IPv4 only), -1 (oneshot - exit after lease), -w (wait for carrier)
		// -t 60 (timeout 60 seconds for carrier + DHCP)
		{"/usr/sbin/dhcpcd", []string{"-4", "-1", "-w", "-t", "60", iface}},
		{"/sbin/dhcpcd", []string{"-4", "-1", "-w", "-t", "60", iface}},
		{"dhcpcd", []string{"-4", "-1", "-w", "-t", "60", iface}},
		// dhclient - most common on Debian/Ubuntu
		{"/usr/sbin/dhclient", []string{"-v", "-1", iface}},
		{"/sbin/dhclient", []string{"-v", "-1", iface}},
		{"dhclient", []string{"-v", "-1", iface}},
		// udhcpc - busybox/embedded
		{"/usr/bin/busybox", []string{"udhcpc", "-i", iface, "-n", "-q"}},
		{"udhcpc", []string{"-i", iface, "-n", "-q"}},
	}

	var lastErr error
	var lastOutput string
	for _, client := range dhcpClients {
		// Check if the binary exists first
		if _, err := exec.LookPath(client.name); err != nil {
			// Binary not found, skip silently
			continue
		}

		log.Info("Attempting DHCP", svc1log.SafeParam("client", client.name), svc1log.SafeParam("iface", iface))
		cmd := exec.Command(client.name, client.args...)
		output, err := cmd.CombinedOutput()
		outputStr := string(output)

		if err == nil {
			log.Info("DHCP client completed successfully", svc1log.SafeParam("client", client.name))
			return nil
		}

		// dhcpcd with -1 may return non-zero even on success in some cases
		// Check if the output indicates success (got an IP offer)
		if strings.Contains(outputStr, "offered") || strings.Contains(outputStr, "leased") ||
			strings.Contains(outputStr, "adding address") {
			log.Info("DHCP client appears to have succeeded despite exit code",
				svc1log.SafeParam("client", client.name),
				svc1log.SafeParam("output", outputStr))
			return nil
		}

		log.Warn("DHCP client failed",
			svc1log.SafeParam("client", client.name),
			svc1log.SafeParam("error", err.Error()),
			svc1log.SafeParam("output", outputStr))
		lastErr = err
		lastOutput = outputStr
	}

	if lastErr != nil {
		return fmt.Errorf("DHCP failed: %v (output: %s)", lastErr, lastOutput)
	}
	return fmt.Errorf("no DHCP client available (tried dhcpcd, dhclient, udhcpc)")
}

// configureDNSForSystemdResolved sets DNS servers for the interface using resolvectl.
// This is needed when bypassing NetworkManager, as DHCP clients may not automatically
// configure systemd-resolved.
func configureDNSForSystemdResolved(ctx context.Context, iface string) {
	log := svc1log.FromContext(ctx)

	// Check if systemd-resolved is in use (127.0.0.53 in resolv.conf)
	resolveData, err := os.ReadFile("/etc/resolv.conf")
	if err != nil || !strings.Contains(string(resolveData), "127.0.0.53") {
		return // Not using systemd-resolved
	}

	log.Debug("systemd-resolved detected, configuring DNS for interface")

	// Try to get DNS servers from dhcpcd lease file
	leaseFiles := []string{
		fmt.Sprintf("/var/lib/dhcpcd/%s.lease", iface),
		fmt.Sprintf("/var/lib/dhcpcd/dhcpcd-%s.lease", iface),
		fmt.Sprintf("/var/lib/dhcp/dhclient.%s.leases", iface),
		fmt.Sprintf("/var/lib/dhclient/dhclient-%s.leases", iface),
	}

	var dnsServers []string
	for _, leaseFile := range leaseFiles {
		data, err := os.ReadFile(leaseFile)
		if err != nil {
			continue
		}
		// Parse DNS servers from lease file
		// dhcpcd format: domain_name_servers='8.8.8.8 8.8.4.4'
		// dhclient format: option domain-name-servers 8.8.8.8,8.8.4.4;
		content := string(data)
		if strings.Contains(content, "domain_name_servers=") {
			// dhcpcd format
			dnsRegex := regexp.MustCompile(`domain_name_servers='([^']+)'`)
			if match := dnsRegex.FindStringSubmatch(content); len(match) > 1 {
				dnsServers = strings.Fields(match[1])
			}
		} else if strings.Contains(content, "domain-name-servers") {
			// dhclient format
			dnsRegex := regexp.MustCompile(`option domain-name-servers ([^;]+);`)
			if match := dnsRegex.FindStringSubmatch(content); len(match) > 1 {
				parts := strings.Split(match[1], ",")
				for _, p := range parts {
					dnsServers = append(dnsServers, strings.TrimSpace(p))
				}
			}
		}
		if len(dnsServers) > 0 {
			log.Debug("Found DNS servers in lease file",
				svc1log.SafeParam("file", leaseFile),
				svc1log.SafeParam("servers", dnsServers))
			break
		}
	}

	// If we couldn't find DNS from lease files, try to get from gateway subnet
	// Common routers use x.x.x.1 as DNS
	if len(dnsServers) == 0 {
		gwCmd := exec.Command("ip", "route", "show", "default", "dev", iface)
		gwOutput, _ := gwCmd.Output()
		gwRegex := regexp.MustCompile(`default via (\d+\.\d+\.\d+\.\d+)`)
		if match := gwRegex.FindStringSubmatch(string(gwOutput)); len(match) > 1 {
			gateway := match[1]
			log.Debug("Using gateway as DNS fallback", svc1log.SafeParam("gateway", gateway))
			dnsServers = []string{gateway}
		}
	}

	// Also add well-known public DNS as fallback
	if len(dnsServers) == 0 {
		log.Debug("No DNS servers found, using public DNS fallback")
		dnsServers = []string{"8.8.8.8", "1.1.1.1"}
	}

	// Apply DNS using resolvectl
	args := append([]string{"dns", iface}, dnsServers...)
	cmd := exec.Command("resolvectl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Warn("Failed to configure DNS via resolvectl",
			svc1log.SafeParam("error", err.Error()),
			svc1log.SafeParam("output", string(output)))
		return
	}

	log.Info("Configured DNS for interface via resolvectl",
		svc1log.SafeParam("iface", iface),
		svc1log.SafeParam("dns", dnsServers))

	// Also set the interface as a DNS interface (not just a link)
	// This ensures queries go through this interface
	_ = exec.Command("resolvectl", "domain", iface, "~.").Run()
}

// waitForDHCPLinux triggers DHCP and waits for an IP address to be assigned on Linux.
func waitForDHCPLinux(ctx context.Context, iface string, timeout int) (acquired bool, ip string, gateway string, dns []string) {
	log := svc1log.FromContext(ctx)

	// First check if we already have an IP (NetworkManager may have handled DHCP)
	cmd := exec.Command("ip", "-4", "addr", "show", iface)
	output, err := cmd.Output()
	if err == nil {
		ipRegex := regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+)`)
		if match := ipRegex.FindStringSubmatch(string(output)); len(match) > 1 {
			existingIP := match[1]
			if !strings.HasPrefix(existingIP, "169.254.") { // Not link-local
				log.Debug("Already have IP address", svc1log.SafeParam("ip", existingIP))
				// IP already assigned, get additional info and return
				return getDHCPInfo(ctx, iface, existingIP)
			}
		}
	}

	// No IP yet - trigger DHCP manually
	// This is needed when using wpa_supplicant directly (non-NetworkManager path)
	log.Info("No IP address yet, triggering DHCP client")
	if err := triggerDHCP(ctx, iface); err != nil {
		log.Warn("Failed to trigger DHCP client", svc1log.SafeParam("error", err.Error()))
		// Continue anyway - maybe NetworkManager will handle it
	}

	// Configure DNS for systemd-resolved systems
	// This is needed because DHCP clients may not automatically configure systemd-resolved
	// when running outside of NetworkManager
	configureDNSForSystemdResolved(ctx, iface)

	// Now wait for IP to be assigned
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for time.Now().Before(deadline) {
		cmd := exec.Command("ip", "-4", "addr", "show", iface)
		output, err := cmd.Output()
		if err == nil {
			ipRegex := regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+)`)
			if match := ipRegex.FindStringSubmatch(string(output)); len(match) > 1 {
				ip = match[1]
				if !strings.HasPrefix(ip, "169.254.") { // Not link-local
					return getDHCPInfo(ctx, iface, ip)
				}
			}
		}
		time.Sleep(1 * time.Second)
	}

	log.Warn("DHCP timeout - no IP acquired")
	return false, "", "", nil
}

// getDHCPInfo retrieves gateway and DNS info for an already-acquired IP.
func getDHCPInfo(ctx context.Context, iface string, ip string) (acquired bool, ipOut string, gateway string, dns []string) {
	log := svc1log.FromContext(ctx)

	// Get gateway
	cmd := exec.Command("ip", "route", "show", "default")
	output, _ := cmd.Output()
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

		// Redirect indicates captive portal
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
			location := resp.Header.Get("Location")
			_ = resp.Body.Close()
			return true, location
		}

		// Check response
		if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			// Firefox returns "success"
			if strings.Contains(string(body), "success") || len(body) == 0 {
				return false, ""
			}
			// Unexpected content might be a portal
			return true, ""
		}
		_ = resp.Body.Close()
	}

	log.Debug("Captive portal check completed - no portal detected")
	return false, ""
}

// checkCommandExists checks if a command is available.
func checkCommandExists(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

// detectNetworkSecurity detects the security type of a target wireless network.
// It uses nmcli or iw to scan for the network and determine its security configuration.
func detectNetworkSecurity(ctx context.Context, interfaceName string, targetSSID string, targetBSSID string) NetworkSecurityType {
	log := svc1log.FromContext(ctx)

	iface := interfaceName
	if iface == "" {
		var err error
		iface, err = findWirelessInterface(ctx)
		if err != nil {
			log.Warn("Could not find wireless interface for security detection")
			return NetworkSecurityUnknown
		}
	}

	// Try nmcli first (most reliable on modern systems)
	if checkCommandExists("nmcli") {
		cmd := exec.Command("nmcli", "-t", "-f", "SSID,BSSID,SECURITY", "device", "wifi", "list", "--rescan", "no")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				parts := strings.Split(line, ":")
				if len(parts) >= 3 {
					ssid := parts[0]
					bssid := strings.ToUpper(strings.Join(parts[1:7], ":")) // BSSID has colons
					security := ""
					if len(parts) >= 8 {
						security = strings.Join(parts[7:], ":") // Security field after BSSID
					}

					// Match by SSID or BSSID
					matchSSID := targetSSID != "" && ssid == targetSSID
					matchBSSID := targetBSSID != "" && strings.EqualFold(bssid, targetBSSID)

					if matchSSID || matchBSSID {
						log.Debug("Found target network security",
							svc1log.SafeParam("ssid", ssid),
							svc1log.SafeParam("security", security))

						return parseNmcliSecurityType(security)
					}
				}
			}
		}
	}

	// Fallback to iw scan (requires root)
	if os.Getuid() == 0 && checkCommandExists("iw") {
		cmd := exec.Command("iw", "dev", iface, "scan")
		output, err := cmd.Output()
		if err == nil {
			return parseIwScanForSecurity(string(output), targetSSID, targetBSSID)
		}
	}

	log.Warn("Could not detect network security type",
		svc1log.SafeParam("target_ssid", targetSSID),
		svc1log.SafeParam("target_bssid", targetBSSID))
	return NetworkSecurityUnknown
}

// parseNmcliSecurityType parses the security string from nmcli output.
func parseNmcliSecurityType(security string) NetworkSecurityType {
	security = strings.ToUpper(security)

	// Check for Enterprise (EAP)
	if strings.Contains(security, "802.1X") || strings.Contains(security, "EAP") {
		return NetworkSecurityEAP
	}

	// Check for PSK (WPA-Personal, WPA2-Personal, WPA3-Personal)
	if strings.Contains(security, "WPA") {
		// WPA without 802.1X is PSK
		return NetworkSecurityPSK
	}

	// Check for WEP (also requires a key, treat as PSK-like)
	if strings.Contains(security, "WEP") {
		return NetworkSecurityPSK
	}

	// Empty or only contains "--" means open
	if security == "" || security == "--" {
		return NetworkSecurityOpen
	}

	return NetworkSecurityUnknown
}

// parseIwScanForSecurity parses iw scan output to find security type for a target network.
func parseIwScanForSecurity(output string, targetSSID string, targetBSSID string) NetworkSecurityType {
	// Split into BSS sections
	bssRegex := regexp.MustCompile(`(?m)^BSS ([0-9a-fA-F:]+)`)
	sections := bssRegex.Split(output, -1)
	matches := bssRegex.FindAllStringSubmatch(output, -1)

	for i, section := range sections[1:] {
		if i >= len(matches) {
			continue
		}
		bssid := strings.ToUpper(matches[i][1])

		// Find SSID in this section
		ssidRegex := regexp.MustCompile(`SSID: (.+)`)
		ssidMatch := ssidRegex.FindStringSubmatch(section)
		ssid := ""
		if len(ssidMatch) > 1 {
			ssid = ssidMatch[1]
		}

		// Check if this is our target
		matchSSID := targetSSID != "" && ssid == targetSSID
		matchBSSID := targetBSSID != "" && strings.EqualFold(bssid, targetBSSID)

		if matchSSID || matchBSSID {
			// Check for RSN (WPA2/WPA3) or WPA IE
			if strings.Contains(section, "RSN:") || strings.Contains(section, "WPA:") {
				// Check for 802.1X (Enterprise)
				if strings.Contains(section, "IEEE 802.1X") || strings.Contains(section, "Authentication suites: 802.1X") {
					return NetworkSecurityEAP
				}
				// PSK authentication
				if strings.Contains(section, "PSK") || strings.Contains(section, "SAE") {
					return NetworkSecurityPSK
				}
				// Has RSN/WPA but unclear auth, assume PSK
				return NetworkSecurityPSK
			}

			// Check for WEP
			if strings.Contains(section, "Privacy") && !strings.Contains(section, "RSN:") && !strings.Contains(section, "WPA:") {
				return NetworkSecurityPSK // WEP also needs a key
			}

			// No security indicators = open
			return NetworkSecurityOpen
		}
	}

	return NetworkSecurityUnknown
}
