package cmd

import (
	"context"
	"fmt"

	// Generated
	connectFern "github.com/Method-Security/infrascan/generated/go/connect"
	// Internal
	wapConnect "github.com/Method-Security/infrascan/internal/connect/wap"
	// External
	"github.com/spf13/cobra"
)

func (a *Infrascan) InitConnectCommand() {
	// Connect Command
	// Subcommands:
	// - wap (wireless access point connection validation)
	connectCmd := &cobra.Command{
		Use:   "connect",
		Short: "Test connectivity and authentication to infrastructure assets",
		Long:  `Test connectivity and authentication to infrastructure assets through controlled connection attempts.`,
	}

	// WAP Command (Wireless Access Point Connection)
	connectWapCmd := &cobra.Command{
		Use:   "wap",
		Short: "Test wireless access point connection and authentication",
		Long: `Test wireless access point security by attempting a full connection with authentication.

Test wireless access point security by attempting a full connection with authentication. This tool is useful
for first directly interacting with a wireless access point to ensure it behaves as expected (correct authentication,
network type, etc.). It does not have to be used to test valid credentials. However, if valid credentials are
obtained or owned, it can secondarily be used to test the validity of those credentials and connect to a target network.
`,
		Run: func(cmd *cobra.Command, args []string) {
			allowDesktopPopups, err := cmd.Flags().GetBool("allow-desktop-popups")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			testOnly, err := cmd.Flags().GetBool("test-only")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			interfaceName, err := cmd.Flags().GetString("interface")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			targetSSID, err := cmd.Flags().GetString("target-ssid")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			targetBSSID, err := cmd.Flags().GetString("target-bssid")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			testPSK, err := cmd.Flags().GetString("test-psk")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			testEAPIdentity, err := cmd.Flags().GetString("test-eap-identity")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			testEAPPassword, err := cmd.Flags().GetString("test-eap-password")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			testPlatformConnectivity, err := cmd.Flags().GetBool("test-platform-connectivity")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			platformURL, err := cmd.Flags().GetString("platform-url")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			returnToOriginal, err := cmd.Flags().GetBool("return-to-original-wifi-if-no-platform-connectivity")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Validate flag combinations
			if testPlatformConnectivity && platformURL == "" {
				a.OutputSignal.AddError(fmt.Errorf("--platform-url is required when --test-platform-connectivity is set"))
				return
			}

			if returnToOriginal && testOnly {
				a.OutputSignal.AddError(fmt.Errorf("--return-to-original-wifi-if-no-platform-connectivity only applies when --test-only=false"))
				return
			}

			// Build config
			config := connectFern.ValidateConnectionConfig{}
			if interfaceName != "" {
				config.Interface = &interfaceName
			}
			if targetSSID != "" {
				config.TargetSsid = &targetSSID
			}
			if targetBSSID != "" {
				config.TargetBssid = &targetBSSID
			}
			if timeout > 0 {
				config.Timeout = &timeout
			}

			// Platform connectivity config
			if testPlatformConnectivity {
				config.TestPlatformConnectivity = &testPlatformConnectivity
				config.PlatformUrl = &platformURL
			}
			if returnToOriginal {
				config.ReturnToOriginalWifiIfNoPlatformConnectivity = &returnToOriginal
			}

			// Build test credentials if provided
			var testCredentials []*connectFern.TestClientProfile
			if testPSK != "" {
				credType := connectFern.TestCredentialTypePskSimple
				profileID := "cli-psk"
				testCredentials = append(testCredentials, &connectFern.TestClientProfile{
					ProfileId:      profileID,
					CredentialType: credType,
					Psk:            &testPSK,
				})
			}
			if testEAPIdentity != "" {
				credType := connectFern.TestCredentialTypeEapTestIdentity
				profileID := "cli-eap"
				testCredentials = append(testCredentials, &connectFern.TestClientProfile{
					ProfileId:      profileID,
					CredentialType: credType,
					EapIdentity:    &testEAPIdentity,
					EapPassword:    &testEAPPassword,
				})
			}
			if len(testCredentials) > 0 {
				config.TestCredentials = testCredentials
			}

			// Run connection
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			ctx = wapConnect.WithAllowDesktopPopups(ctx, allowDesktopPopups)
			ctx = wapConnect.WithTestOnly(ctx, testOnly)
			if platformURL != "" {
				ctx = wapConnect.WithPlatformURL(ctx, platformURL)
			}

			report, err := wapConnect.ValidateConnection(ctx, config)
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			if report != nil {
				a.OutputSignal.Content = report
			}
		},
	}

	// Target Flags
	connectWapCmd.Flags().String("target-ssid", "", "Target SSID to connect to")
	connectWapCmd.Flags().String("target-bssid", "", "Target BSSID to connect to (optional, for specific AP)")
	connectWapCmd.Flags().String("interface", "", "Network interface to use (auto-detected if not specified)")
	connectWapCmd.Flags().Int("timeout", 60, "Timeout in seconds for connection attempt")

	// Test mode flag
	// NOTE: Boolean flags require = syntax: --test-only=false, NOT --test-only false
	connectWapCmd.Flags().Bool("test-only", true,
		"Test connection and restore original WiFi when done. Use --test-only=false (with =) to stay connected on success.")

	// Credential flags
	connectWapCmd.Flags().String("test-psk", "", "PSK/password to test for WPA-Personal networks")
	connectWapCmd.Flags().String("test-eap-identity", "", "EAP identity for WPA-Enterprise testing")
	connectWapCmd.Flags().String("test-eap-password", "", "EAP password for WPA-Enterprise testing")

	// Platform connectivity flags
	connectWapCmd.Flags().Bool("test-platform-connectivity", false,
		"After successful connection, test HTTP connectivity to --platform-url")
	connectWapCmd.Flags().String("platform-url", "",
		"URL to test for platform connectivity (e.g., https://api.example.com/health). "+
			"Required when --test-platform-connectivity is set. Follows redirects, expects HTTP 200.")
	connectWapCmd.Flags().Bool("return-to-original-wifi-if-no-platform-connectivity", false,
		"Only applies when --test-only=false. Use =true to disconnect from target and restore original WiFi when platform connectivity fails.")

	// Advanced flags
	connectWapCmd.Flags().Bool("allow-desktop-popups", false,
		"Allow desktop/OS password prompts (NetworkManager secret agent) on authentication failures. "+
			"By default, infrascan uses a non-NetworkManager path when running as root to avoid GUI prompts.")

	// Add wap command to 'connect' command
	connectCmd.AddCommand(connectWapCmd)

	// Add connect command to root
	a.RootCmd.AddCommand(connectCmd)
}
