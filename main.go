package main

import (
	"os"

	"github.com/Method-Security/infrascan/cmd"
)

var version = "none"

func main() {
	infrascan := cmd.NewInfrascan(version)
	infrascan.InitRootCommand()
	infrascan.InitDiscoverCommand()
	infrascan.InitConnectCommand()

	if err := infrascan.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
