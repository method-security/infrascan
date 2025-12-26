package cmd

import (
	// Generated
	discoverFern "github.com/Method-Security/infrascan/generated/go/discover"
	// Internal
	wapsDiscover "github.com/Method-Security/infrascan/internal/discover/waps"
	// External
	"github.com/spf13/cobra"
)

func (a *Infrascan) InitDiscoverCommand() {
	// Discover Command
	// Subcommands:
	// - waps (wireless access points)
	discoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover infrastructure assets",
		Long:  `Discover infrastructure assets such as wireless access points and network resources.`,
	}

	// WAPS Command (Wireless Access Points)
	discoverWapsCmd := &cobra.Command{
		Use:   "waps",
		Short: "Discover wireless access points",
		Long: `Discover and enumerate wireless access points in the environment.

This command performs 802.11 reconnaissance to discover nearby wireless
access points. It extracts information from beacon frames including:

  - Identity: BSSID, SSID (including hidden network detection)
  - Radio: Channel, frequency band, signal strength, channel width
  - Security: Authentication method, encryption, WPA version, PMF policy
  - Capabilities: WiFi generation (4/5/6/7), MIMO support
  - Vendor: OUI-based manufacturer identification
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

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			passive, err := cmd.Flags().GetBool("passive")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Build config
			config := discoverFern.DiscoverWapsConfig{}
			if interfaceName != "" {
				config.Interface = &interfaceName
			}
			if targetSSID != "" {
				config.TargetSsid = &targetSSID
			}
			if timeout > 0 {
				config.Timeout = &timeout
			}
			config.Passive = &passive

			// Run discovery
			report, err := wapsDiscover.DiscoverWaps(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverWapsCmd.Flags().String("target-ssid", "", "Target SSID to discover (optional, filters results)")
	discoverWapsCmd.Flags().String("interface", "", "Network interface to use for scanning (auto-detected if not specified)")
	discoverWapsCmd.Flags().Int("timeout", 30, "Timeout in seconds for the discovery scan")
	discoverWapsCmd.Flags().Bool("passive", false, "Enable passive mode (zero RF emissions, requires monitor mode and elevated privileges)")

	// Add waps command to 'discover' command
	discoverCmd.AddCommand(discoverWapsCmd)

	// Add discover command to root
	a.RootCmd.AddCommand(discoverCmd)
}
