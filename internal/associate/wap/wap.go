// Package wap handles wireless access point association validation.
// It attempts to connect to target networks using test credentials and
// records the outcomes to validate security controls.
package wap

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/Method-Security/infrascan/generated/go/associate"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

type allowDesktopPopupsCtxKey struct{}

// WithAllowDesktopPopups sets whether infrascan is allowed to trigger desktop/OS
// password dialogs (e.g., NetworkManager secret agent popups) during association attempts.
//
// Default behavior should be "false" (no popups). If popups are disallowed, platform
// implementations may refuse to attempt certain association operations that are known
// to trigger OS UI on authentication failure.
func WithAllowDesktopPopups(ctx context.Context, allow bool) context.Context {
	return context.WithValue(ctx, allowDesktopPopupsCtxKey{}, allow)
}

func allowDesktopPopups(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v := ctx.Value(allowDesktopPopupsCtxKey{})
	allowed, ok := v.(bool)
	return ok && allowed
}

type testOnlyCtxKey struct{}

// WithTestOnly sets whether infrascan should disconnect and restore the original
// WiFi connection after a successful connection test.
//
// When testOnly is true (default): After testing, disconnect from the target network
// and restore the original WiFi connection.
//
// When testOnly is false: Stay connected to the target network on success.
// The original network will NOT be restored.
func WithTestOnly(ctx context.Context, testOnly bool) context.Context {
	return context.WithValue(ctx, testOnlyCtxKey{}, testOnly)
}

func isTestOnly(ctx context.Context) bool {
	if ctx == nil {
		return true // Default to test-only mode
	}
	v := ctx.Value(testOnlyCtxKey{})
	testOnly, ok := v.(bool)
	if !ok {
		return true // Default to test-only mode
	}
	return testOnly
}

type platformURLCtxKey struct{}

// WithPlatformURL sets the URL to test for platform connectivity after successful connection.
func WithPlatformURL(ctx context.Context, url string) context.Context {
	return context.WithValue(ctx, platformURLCtxKey{}, url)
}

func getPlatformURL(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v := ctx.Value(platformURLCtxKey{})
	url, ok := v.(string)
	if !ok {
		return ""
	}
	return url
}

// NetworkSecurityType represents the detected security type of a wireless network.
type NetworkSecurityType int

const (
	// NetworkSecurityUnknown indicates the security type could not be determined.
	NetworkSecurityUnknown NetworkSecurityType = iota
	// NetworkSecurityOpen indicates an open network with no authentication required.
	NetworkSecurityOpen
	// NetworkSecurityPSK indicates WPA/WPA2/WPA3-Personal requiring a pre-shared key.
	NetworkSecurityPSK
	// NetworkSecurityEAP indicates WPA/WPA2/WPA3-Enterprise requiring EAP identity/password.
	NetworkSecurityEAP
)

// String returns a human-readable name for the security type.
func (s NetworkSecurityType) String() string {
	switch s {
	case NetworkSecurityOpen:
		return "Open"
	case NetworkSecurityPSK:
		return "WPA-Personal (PSK)"
	case NetworkSecurityEAP:
		return "WPA-Enterprise (EAP)"
	default:
		return "Unknown"
	}
}

// validateCredentialsForSecurity checks that the required credentials are provided
// for the detected network security type. Returns an error with a clear message
// about what credentials are needed rather than prompting the user interactively.
func validateCredentialsForSecurity(securityType NetworkSecurityType, testCredentials []*associate.TestClientProfile) error {
	switch securityType {
	case NetworkSecurityOpen:
		// Open networks don't require credentials
		return nil

	case NetworkSecurityPSK:
		// PSK networks require a pre-shared key (8-63 characters per WPA spec)
		for _, cred := range testCredentials {
			if cred.CredentialType == associate.TestCredentialTypePskSimple ||
				cred.CredentialType == associate.TestCredentialTypePskCommon {
				if cred.Psk != nil && *cred.Psk != "" {
					pskLen := len(*cred.Psk)
					if pskLen < 8 {
						return fmt.Errorf("invalid PSK: password is %d characters but WPA/WPA2 requires 8-63 characters. "+
							"Please provide a valid pre-shared key", pskLen)
					}
					if pskLen > 63 {
						return fmt.Errorf("invalid PSK: password is %d characters but WPA/WPA2 requires 8-63 characters. "+
							"Please provide a valid pre-shared key", pskLen)
					}
					return nil // PSK provided and valid length
				}
			}
		}
		return fmt.Errorf("no credentials provided: target network requires WPA-Personal (PSK) authentication. " +
			"Please provide the pre-shared key using --test-psk <password>")

	case NetworkSecurityEAP:
		// EAP networks require identity and password
		for _, cred := range testCredentials {
			if cred.CredentialType == associate.TestCredentialTypeEapTestIdentity ||
				cred.CredentialType == associate.TestCredentialTypeEapGuest {
				if cred.EapIdentity != nil && *cred.EapIdentity != "" {
					// Password can be empty for some EAP methods, but identity is required
					return nil // EAP credentials provided
				}
			}
		}
		return fmt.Errorf("no credentials provided: target network requires WPA-Enterprise (EAP) authentication. " +
			"Please provide the EAP identity and password using --test-eap-identity <identity> --test-eap-password <password>")

	case NetworkSecurityUnknown:
		// If we can't determine security type, we need explicit credentials
		if len(testCredentials) == 0 {
			return fmt.Errorf("no credentials provided and network security type could not be determined. " +
				"Please provide credentials explicitly: " +
				"for WPA-Personal use --test-psk <password>, " +
				"for WPA-Enterprise use --test-eap-identity <identity> --test-eap-password <password>, " +
				"or the network may be open and no credentials are needed")
		}
		return nil
	}
	return nil
}

// ValidateAssociation performs active association validation against a target
// wireless network. It attempts to connect using test credentials based on
// the detected security configuration and records outcomes.
func ValidateAssociation(ctx context.Context, config associate.ValidateAssociationConfig) (*associate.ValidateAssociationReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	interfaceName := ""
	if config.Interface != nil {
		interfaceName = *config.Interface
	}

	targetSSID := ""
	if config.TargetSsid != nil {
		targetSSID = *config.TargetSsid
	}

	targetBSSID := ""
	if config.TargetBssid != nil {
		targetBSSID = *config.TargetBssid
	}

	timeout := 60
	if config.Timeout != nil {
		timeout = *config.Timeout
	}

	log.Info("Starting wireless connection test",
		svc1log.SafeParam("interface", interfaceName),
		svc1log.SafeParam("target_ssid", targetSSID),
		svc1log.SafeParam("target_bssid", targetBSSID),
		svc1log.SafeParam("timeout", timeout),
		svc1log.SafeParam("os", runtime.GOOS))

	// Validate target is specified
	if targetSSID == "" && targetBSSID == "" {
		return nil, fmt.Errorf("either target-ssid or target-bssid must be specified")
	}

	// Find wireless interface if not specified
	if interfaceName == "" {
		var err error
		interfaceName, err = findWirelessInterface(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to find wireless interface: %w", err)
		}
		log.Info("Auto-detected wireless interface", svc1log.SafeParam("interface", interfaceName))
	}

	// Capture original network state - we always save and restore
	// This is core to the "associate" command's non-destructive behavior
	log.Info("Capturing current WiFi connection state")
	originalNetwork := captureOriginalNetwork(ctx, interfaceName)
	if originalNetwork.WasConnected {
		log.Info("Currently connected to WiFi, will restore after validation",
			svc1log.SafeParam("original_ssid", ptrStr(originalNetwork.Ssid)))
		
		// Disconnect from current network before testing
		log.Info("Disconnecting from current network for validation")
		if err := disconnectFromNetwork(ctx, interfaceName); err != nil {
			log.Warn("Failed to disconnect from current network",
				svc1log.SafeParam("error", err.Error()))
			errors = append(errors, fmt.Sprintf("disconnect failed: %v", err))
		}
		// Give time for disconnection to complete
		time.Sleep(2 * time.Second)
	} else {
		log.Info("Not currently connected to WiFi")
	}

	// Perform association attempts
	attempts := []*associate.AssociationAttempt{}
	var findings []*associate.Finding

	// Detect target network's security type before attempting connection
	securityType := detectNetworkSecurity(ctx, interfaceName, targetSSID, targetBSSID)
	log.Info("Detected target network security",
		svc1log.SafeParam("security_type", securityType),
		svc1log.SafeParam("target_ssid", targetSSID))

	// Validate that required credentials are provided (no prompts, explicit errors)
	testCredentials := config.TestCredentials
	if err := validateCredentialsForSecurity(securityType, testCredentials); err != nil {
		return nil, err
	}

	// If no credentials provided and network is open, use default no-credential profile
	if len(testCredentials) == 0 {
		if securityType == NetworkSecurityOpen {
			noCredType := associate.TestCredentialTypeNone
			testCredentials = []*associate.TestClientProfile{
				{
					ProfileId:      "default-none",
					CredentialType: noCredType,
				},
			}
		}
		// If security type required credentials, validateCredentialsForSecurity would have returned error
	}

	connectionSucceeded := false
	var platformResult *associate.PlatformConnectivityResult
	for _, cred := range testCredentials {
		log.Info("Attempting connection with credential profile",
			svc1log.SafeParam("profile_id", cred.ProfileId),
			svc1log.SafeParam("credential_type", cred.CredentialType))

		attemptResult := performAssociationAttempt(ctx, interfaceName, targetSSID, targetBSSID, cred, timeout)
		attempt := attemptResult.Attempt
		attempts = append(attempts, attempt)

		// Log outcome
		log.Info("Connection attempt completed",
			svc1log.SafeParam("outcome", attempt.Outcome),
			svc1log.SafeParam("ip_acquired", ptrBool(attempt.IpAcquired)),
			svc1log.SafeParam("portal_detected", ptrBool(attempt.PortalDetected)))

		// Generate findings based on outcome
		attemptFindings := analyzeAttempt(attempt, cred)
		findings = append(findings, attemptFindings...)

		// If successful with this credential, we can stop trying
		if attempt.Outcome == associate.AssociationOutcomeSuccess {
			connectionSucceeded = true
			// If platform connectivity was tested during connection (wpa_supplicant path),
			// capture that result to avoid testing again after wpa_supplicant is killed
			if attemptResult.PlatformConnectivity != nil {
				platformResult = attemptResult.PlatformConnectivity
			}
			break
		}
	}

	// Test platform connectivity if enabled and connection succeeded
	// Only test if we haven't already captured a result during connection
	if platformResult == nil {
		if connectionSucceeded && config.TestPlatformConnectivity != nil && *config.TestPlatformConnectivity {
			// Connection succeeded and we need to test platform connectivity
			// This works for nmcli path where connection stays up after function returns
			platformResult = testPlatformConnectivity(ctx, config.PlatformUrl)
		} else {
			// Not tested
			platformResult = &associate.PlatformConnectivityResult{
				Tested: false,
			}
		}
	}

	// Determine whether to restore original network or stay connected
	testOnly := isTestOnly(ctx)
	networkRestored := false

	// Check if we should return to original due to platform connectivity failure
	returnDueToPlatformFailure := false
	if !testOnly && connectionSucceeded && platformResult.Tested {
		if config.ReturnToOriginalWifiIfNoPlatformConnectivity != nil &&
			*config.ReturnToOriginalWifiIfNoPlatformConnectivity &&
			(platformResult.Success == nil || !*platformResult.Success) {
			returnDueToPlatformFailure = true
			log.Info("Platform connectivity test failed, will return to original network",
				svc1log.SafeParam("url", ptrStr(platformResult.Url)))
		}
	}

	if !testOnly && connectionSucceeded && !returnDueToPlatformFailure {
		// User wants to stay connected to the target network
		log.Info("Connection successful, staying connected to target network (--test-only=false)",
			svc1log.SafeParam("target_ssid", targetSSID))
		// Mark that we intentionally did not restore
		if originalNetwork != nil {
			originalNetwork.RestoredSuccessfully = ptr(false)
			skipMsg := "not restored: --test-only=false and connection succeeded"
			if platformResult.Tested && platformResult.Success != nil && *platformResult.Success {
				skipMsg = "not restored: --test-only=false, connection succeeded, and platform connectivity verified"
			}
			originalNetwork.RestoreError = &skipMsg
		}
	} else if originalNetwork != nil && originalNetwork.WasConnected {
		// Test-only mode OR connection failed OR platform connectivity failed: restore original network
		restoreReason := "test-only mode"
		if !connectionSucceeded {
			restoreReason = "connection failed"
		} else if returnDueToPlatformFailure {
			restoreReason = "platform connectivity failed"
		}

		log.Info("Restoring connection to original network",
			svc1log.SafeParam("original_ssid", ptrStr(originalNetwork.Ssid)),
			svc1log.SafeParam("reason", restoreReason))

		// First disconnect from test network
		_ = disconnectFromNetwork(ctx, interfaceName)
		time.Sleep(1 * time.Second)

		// Reconnect to original network
		if err := reconnectToOriginalNetwork(ctx, interfaceName, originalNetwork); err != nil {
			log.Warn("Failed to restore original network connection",
				svc1log.SafeParam("error", err.Error()))
			errors = append(errors, fmt.Sprintf("restore failed: %v", err))
			failedMsg := err.Error()
			originalNetwork.RestoredSuccessfully = ptr(false)
			originalNetwork.RestoreError = &failedMsg
			if returnDueToPlatformFailure {
				platformResult.ReturnedToOriginal = ptr(false)
			}
		} else {
			log.Info("Successfully restored original network connection")
			originalNetwork.RestoredSuccessfully = ptr(true)
			networkRestored = true
			if returnDueToPlatformFailure {
				platformResult.ReturnedToOriginal = ptr(true)
			}
		}
	}

	// Build result
	result := &associate.ValidateAssociationResult{
		Attempts:                attempts,
		Findings:                findings,
		OriginalNetworkRestored: &networkRestored,
		OriginalNetwork:         originalNetwork,
		PlatformConnectivity:    platformResult,
	}

	report := &associate.ValidateAssociationReport{
		Config: &config,
		Result: result,
		Errors: errors,
	}

	log.Info("Completed wireless connection test",
		svc1log.SafeParam("attempts", len(attempts)),
		svc1log.SafeParam("findings", len(findings)),
		svc1log.SafeParam("errors", len(errors)))

	return report, nil
}

// performAssociationAttemptResult holds both the attempt and any platform connectivity result
// captured during the connection (for wpa_supplicant path where connectivity must be tested
// while the supplicant is running).
type performAssociationAttemptResult struct {
	Attempt              *associate.AssociationAttempt
	PlatformConnectivity *associate.PlatformConnectivityResult
}

// performAssociationAttempt executes a single association attempt with the given credentials.
// It returns both the attempt details and any platform connectivity result that was captured
// during the connection (for connections that require testing while wpa_supplicant is active).
func performAssociationAttempt(
	ctx context.Context,
	interfaceName string,
	targetSSID string,
	targetBSSID string,
	cred *associate.TestClientProfile,
	timeout int,
) *performAssociationAttemptResult {
	startTime := time.Now()

	attempt := &associate.AssociationAttempt{
		StartTime:          startTime,
		CredentialTypeUsed: &cred.CredentialType,
	}

	if targetSSID != "" {
		attempt.Ssid = &targetSSID
	}
	if targetBSSID != "" {
		attempt.Bssid = &targetBSSID
	}

	// Get signal quality before attempting connection
	signalQuality := getSignalQuality(ctx, interfaceName, targetSSID, targetBSSID)
	if signalQuality != 0 {
		attempt.SignalQualityAtAttempt = &signalQuality
	}

	// Perform platform-specific association
	result := connectToNetwork(ctx, interfaceName, targetSSID, targetBSSID, cred, timeout)

	endTime := time.Now()
	attempt.EndTime = &endTime
	attempt.Outcome = result.Outcome
	attempt.StatusCode = result.StatusCode
	attempt.StatusCodeRaw = result.StatusCodeRaw
	attempt.ReasonCode = result.ReasonCode
	attempt.ReasonCodeRaw = result.ReasonCodeRaw
	attempt.HandshakeProgress = result.HandshakeProgress
	attempt.Timing = result.Timing
	attempt.RetryCount = result.RetryCount
	attempt.AttemptedSecurity = result.AttemptedSecurity
	attempt.NegotiatedSecurity = result.NegotiatedSecurity
	attempt.IpAcquired = result.IpAcquired
	attempt.IpAddress = result.IpAddress
	attempt.DhcpServer = result.DhcpServer
	attempt.Gateway = result.Gateway
	attempt.DnsServers = result.DnsServers
	attempt.PortalDetected = result.PortalDetected
	attempt.PortalUrl = result.PortalUrl
	attempt.EapMethodNegotiated = result.EapMethodNegotiated
	attempt.ErrorMessage = result.ErrorMessage

	return &performAssociationAttemptResult{
		Attempt:              attempt,
		PlatformConnectivity: result.PlatformConnectivity,
	}
}

// analyzeAttempt generates findings based on association attempt results.
func analyzeAttempt(attempt *associate.AssociationAttempt, cred *associate.TestClientProfile) []*associate.Finding {
	var findings []*associate.Finding

	// Check if open network connected successfully
	if attempt.Outcome == associate.AssociationOutcomeSuccess && cred.CredentialType == associate.TestCredentialTypeNone {
		// Check if network is truly open (no authentication required)
		if attempt.IpAcquired != nil && *attempt.IpAcquired {
			if attempt.PortalDetected == nil || !*attempt.PortalDetected {
				// Open network with direct IP access - potential security concern
				finding := &associate.Finding{
					Id:          "OPEN-NETWORK-ACCESS",
					Title:       "Open Network Allows Direct Access",
					Description: ptr("The network allows connection without authentication and provides direct IP access without a captive portal."),
					Severity:    associate.FindingSeverityMedium,
					Category:    associate.FindingCategorySecurityWeakness,
					RelatedSsid: attempt.Ssid,
				}
				findings = append(findings, finding)
			}
		}
	}

	// Check for weak PSK acceptance
	if attempt.Outcome == associate.AssociationOutcomeSuccess && cred.CredentialType == associate.TestCredentialTypePskCommon {
		finding := &associate.Finding{
			Id:            "WEAK-PSK-ACCEPTED",
			Title:         "Weak PSK Accepted",
			Description:   ptr("The network accepted a common/weak PSK password."),
			Severity:      associate.FindingSeverityHigh,
			Category:      associate.FindingCategorySecurityWeakness,
			RelatedSsid:   attempt.Ssid,
			RelatedBssid:  attempt.Bssid,
			Evidence:      ptr(fmt.Sprintf("Credential type: %s", cred.CredentialType)),
			Recommendation: ptr("Use a strong, unique PSK with at least 16 characters."),
		}
		findings = append(findings, finding)
	}

	// Check for captive portal without proper redirect
	if attempt.PortalDetected != nil && *attempt.PortalDetected {
		finding := &associate.Finding{
			Id:          "CAPTIVE-PORTAL-DETECTED",
			Title:       "Captive Portal Detected",
			Description: ptr("A captive portal was detected on this network."),
			Severity:    associate.FindingSeverityInfo,
			Category:    associate.FindingCategoryUnexpectedBehavior,
			RelatedSsid: attempt.Ssid,
		}
		if attempt.PortalUrl != nil {
			finding.Evidence = attempt.PortalUrl
		}
		findings = append(findings, finding)
	}

	// Check for PMF not being negotiated on WPA3
	if attempt.NegotiatedSecurity != nil {
		if attempt.NegotiatedSecurity.WpaVersion != nil &&
			*attempt.NegotiatedSecurity.WpaVersion == "WPA3" &&
			(attempt.NegotiatedSecurity.PmfNegotiated == nil || !*attempt.NegotiatedSecurity.PmfNegotiated) {
			finding := &associate.Finding{
				Id:             "WPA3-NO-PMF",
				Title:          "WPA3 Without Protected Management Frames",
				Description:    ptr("WPA3 connection was established but PMF was not negotiated."),
				Severity:       associate.FindingSeverityMedium,
				Category:       associate.FindingCategoryConfigurationIssue,
				RelatedSsid:    attempt.Ssid,
				Recommendation: ptr("Ensure PMF is required for WPA3 networks."),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// testPlatformConnectivity makes an HTTP request to the specified URL and returns the result.
// It follows redirects and checks for an HTTP 200 response.
func testPlatformConnectivity(ctx context.Context, urlPtr *string) *associate.PlatformConnectivityResult {
	log := svc1log.FromContext(ctx)

	result := &associate.PlatformConnectivityResult{
		Tested: true,
	}

	if urlPtr == nil || *urlPtr == "" {
		result.Tested = false
		errMsg := "no URL provided"
		result.Error = &errMsg
		return result
	}

	url := *urlPtr
	result.Url = &url

	log.Info("Testing platform connectivity", svc1log.SafeParam("url", url))

	// Create HTTP client that follows redirects
	client := &http.Client{
		Timeout: 30 * time.Second,
		// Default behavior follows redirects (up to 10)
	}

	startTime := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		errMsg := fmt.Sprintf("failed to create request: %v", err)
		result.Error = &errMsg
		success := false
		result.Success = &success
		log.Warn("Platform connectivity test failed", svc1log.SafeParam("error", errMsg))
		return result
	}

	// Set a reasonable user agent
	req.Header.Set("User-Agent", "infrascan/1.0 (platform-connectivity-test)")

	resp, err := client.Do(req)
	responseTime := int(time.Since(startTime).Milliseconds())
	result.ResponseTimeMs = &responseTime

	if err != nil {
		errMsg := fmt.Sprintf("request failed: %v", err)
		result.Error = &errMsg
		success := false
		result.Success = &success
		log.Warn("Platform connectivity test failed",
			svc1log.SafeParam("error", errMsg),
			svc1log.SafeParam("response_time_ms", responseTime))
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = &resp.StatusCode
	success := resp.StatusCode == http.StatusOK
	result.Success = &success

	if success {
		log.Info("Platform connectivity test passed",
			svc1log.SafeParam("status_code", resp.StatusCode),
			svc1log.SafeParam("response_time_ms", responseTime))
	} else {
		errMsg := fmt.Sprintf("unexpected status code: %d", resp.StatusCode)
		result.Error = &errMsg
		log.Warn("Platform connectivity test failed",
			svc1log.SafeParam("status_code", resp.StatusCode),
			svc1log.SafeParam("response_time_ms", responseTime))
	}

	return result
}

// captureOriginalNetwork records the current WiFi connection state.
func captureOriginalNetwork(ctx context.Context, interfaceName string) *associate.OriginalNetworkState {
	ssid, bssid, connected := getCurrentConnection(ctx, interfaceName)

	state := &associate.OriginalNetworkState{
		WasConnected: connected,
	}

	if connected {
		if ssid != "" {
			state.Ssid = &ssid
		}
		if bssid != "" {
			state.Bssid = &bssid
		}
		// Capture the connection profile name (Linux: NetworkManager profile, Windows: profile name)
		// This is more reliable for restoration than SSID-based reconnection
		profileName := getConnectionProfileName(ctx, interfaceName)
		if profileName != "" {
			state.ConnectionProfile = &profileName
		}
	}

	return state
}

// Helper functions for pointer handling
func ptr[T any](v T) *T {
	return &v
}

func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func ptrBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

