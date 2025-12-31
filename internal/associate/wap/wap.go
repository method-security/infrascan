// Package wap handles wireless access point association validation.
// It attempts to connect to target networks using test credentials and
// records the outcomes to validate security controls.
package wap

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/Method-Security/infrascan/generated/go/associate"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

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

	breakAndRemake := false
	if config.BreakAndRemakeWifiAssociation != nil {
		breakAndRemake = *config.BreakAndRemakeWifiAssociation
	}

	log.Info("Starting wireless association validation",
		svc1log.SafeParam("interface", interfaceName),
		svc1log.SafeParam("target_ssid", targetSSID),
		svc1log.SafeParam("target_bssid", targetBSSID),
		svc1log.SafeParam("timeout", timeout),
		svc1log.SafeParam("break_and_remake", breakAndRemake),
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

	// Capture original network state if break-and-remake is enabled
	var originalNetwork *associate.OriginalNetworkState
	if breakAndRemake {
		log.Info("Checking current WiFi connection for break-and-remake")
		originalNetwork = captureOriginalNetwork(ctx, interfaceName)
		if originalNetwork.WasConnected {
			log.Info("Currently connected to WiFi, will restore after validation",
				svc1log.SafeParam("original_ssid", ptrStr(originalNetwork.Ssid)))
		} else {
			log.Info("Not currently connected to WiFi, skipping break-and-remake logic")
		}
	}

	// Disconnect from current network if needed
	if breakAndRemake && originalNetwork != nil && originalNetwork.WasConnected {
		log.Info("Disconnecting from current network for validation")
		if err := disconnectFromNetwork(ctx, interfaceName); err != nil {
			log.Warn("Failed to disconnect from current network",
				svc1log.SafeParam("error", err.Error()))
			errors = append(errors, fmt.Sprintf("disconnect failed: %v", err))
		}
		// Give time for disconnection to complete
		time.Sleep(2 * time.Second)
	}

	// Perform association attempts
	attempts := []*associate.AssociationAttempt{}
	var findings []*associate.Finding

	// Try connecting with different credential types based on config
	testCredentials := config.TestCredentials
	if len(testCredentials) == 0 {
		// Default: try no credentials (for open networks)
		noCredType := associate.TestCredentialTypeNone
		testCredentials = []*associate.TestClientProfile{
			{
				ProfileId:      "default-none",
				CredentialType: noCredType,
			},
		}
	}

	for _, cred := range testCredentials {
		log.Info("Attempting association with credential profile",
			svc1log.SafeParam("profile_id", cred.ProfileId),
			svc1log.SafeParam("credential_type", cred.CredentialType))

		attempt := performAssociationAttempt(ctx, interfaceName, targetSSID, targetBSSID, cred, timeout)
		attempts = append(attempts, attempt)

		// Log outcome
		log.Info("Association attempt completed",
			svc1log.SafeParam("outcome", attempt.Outcome),
			svc1log.SafeParam("ip_acquired", ptrBool(attempt.IpAcquired)),
			svc1log.SafeParam("portal_detected", ptrBool(attempt.PortalDetected)))

		// Generate findings based on outcome
		attemptFindings := analyzeAttempt(attempt, cred)
		findings = append(findings, attemptFindings...)

		// If successful with this credential, we can stop trying
		if attempt.Outcome == associate.AssociationOutcomeSuccess {
			break
		}
	}

	// Restore original network connection if break-and-remake was used
	networkRestored := false
	if breakAndRemake && originalNetwork != nil && originalNetwork.WasConnected {
		log.Info("Restoring connection to original network",
			svc1log.SafeParam("original_ssid", ptrStr(originalNetwork.Ssid)))

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
		} else {
			log.Info("Successfully restored original network connection")
			originalNetwork.RestoredSuccessfully = ptr(true)
			networkRestored = true
		}
	}

	// Build result
	result := &associate.ValidateAssociationResult{
		Attempts:                attempts,
		Findings:                findings,
		OriginalNetworkRestored: &networkRestored,
		OriginalNetwork:         originalNetwork,
	}

	report := &associate.ValidateAssociationReport{
		Config: &config,
		Result: result,
		Errors: errors,
	}

	log.Info("Completed wireless association validation",
		svc1log.SafeParam("attempts", len(attempts)),
		svc1log.SafeParam("findings", len(findings)),
		svc1log.SafeParam("errors", len(errors)))

	return report, nil
}

// performAssociationAttempt executes a single association attempt with the given credentials.
func performAssociationAttempt(
	ctx context.Context,
	interfaceName string,
	targetSSID string,
	targetBSSID string,
	cred *associate.TestClientProfile,
	timeout int,
) *associate.AssociationAttempt {
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

	return attempt
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

