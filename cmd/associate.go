package cmd

import (
	// Generated
	associateFern "github.com/Method-Security/infrascan/generated/go/associate"
	// Internal
	wapAssociate "github.com/Method-Security/infrascan/internal/associate/wap"
	// External
	"github.com/spf13/cobra"
)

func (a *Infrascan) InitAssociateCommand() {
	// Associate Command
	// Subcommands:
	// - wap (wireless access point association validation)
	associateCmd := &cobra.Command{
		Use:   "associate",
		Short: "Validate infrastructure asset access controls",
		Long:  `Validate infrastructure asset access controls through controlled association attempts.`,
	}

	// WAP Command (Wireless Access Point Association)
	associateWapCmd := &cobra.Command{
		Use:   "wap",
		Short: "Validate wireless access point association",
		Long: `Validate wireless access point security by attempting controlled associations.

This command performs Active Association Validation to confirm that an SSID/AP
actually enforces the advertised security and expected access controls.

The tool will:
  - Attempt to associate/connect using test credentials based on security type
  - Collect high-level outcomes (success/failure, negotiated security, DHCP, portal)
  - Record the actual security properties negotiated during connection
  - Detect captive portals and authentication requirements

For open networks, it will attempt connection without credentials.
For PSK networks, it will try common/weak passwords.
For Enterprise networks, it will attempt with test identities.

Use --break-and-remake-wifi-association to temporarily disconnect from your
current WiFi network, perform the test, and then reconnect to your original
network automatically.

Security Note: This tool performs authorized validation only. No credential
guessing beyond simple test identities. No disruption to target networks.
`,
		Run: func(cmd *cobra.Command, args []string) {
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

			breakAndRemake, err := cmd.Flags().GetBool("break-and-remake-wifi-association")
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

			// Build config
			config := associateFern.ValidateAssociationConfig{}
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
			config.BreakAndRemakeWifiAssociation = &breakAndRemake

			// Build test credentials if provided
			var testCredentials []*associateFern.TestClientProfile
			if testPSK != "" {
				credType := associateFern.TestCredentialTypePskSimple
				profileId := "cli-psk"
				testCredentials = append(testCredentials, &associateFern.TestClientProfile{
					ProfileId:      profileId,
					CredentialType: credType,
					Psk:            &testPSK,
				})
			}
			if testEAPIdentity != "" {
				credType := associateFern.TestCredentialTypeEapTestIdentity
				profileId := "cli-eap"
				testCredentials = append(testCredentials, &associateFern.TestClientProfile{
					ProfileId:      profileId,
					CredentialType: credType,
					EapIdentity:    &testEAPIdentity,
					EapPassword:    &testEAPPassword,
				})
			}
			if len(testCredentials) > 0 {
				config.TestCredentials = testCredentials
			}

			// Run association validation
			report, err := wapAssociate.ValidateAssociation(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			if report != nil {
				a.OutputSignal.Content = report
			}
		},
	}

	// Target Flags
	associateWapCmd.Flags().String("target-ssid", "", "Target SSID to attempt association with")
	associateWapCmd.Flags().String("target-bssid", "", "Target BSSID to attempt association with (optional, for specific AP)")
	associateWapCmd.Flags().String("interface", "", "Network interface to use (auto-detected if not specified)")
	associateWapCmd.Flags().Int("timeout", 60, "Timeout in seconds for association attempt")

	// Break and remake flag
	associateWapCmd.Flags().Bool("break-and-remake-wifi-association", false,
		"If connected to WiFi, disconnect, perform test, then reconnect to original network")

	// Test credential flags
	associateWapCmd.Flags().String("test-psk", "", "PSK/password to test for WPA-Personal networks")
	associateWapCmd.Flags().String("test-eap-identity", "", "EAP identity for WPA-Enterprise testing")
	associateWapCmd.Flags().String("test-eap-password", "", "EAP password for WPA-Enterprise testing")

	// Add wap command to 'associate' command
	associateCmd.AddCommand(associateWapCmd)

	// Add associate command to root
	a.RootCmd.AddCommand(associateCmd)
}

