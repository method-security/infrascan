package main

import (
	"flag"
	"os"

	"github.com/Method-Security/infrascan/cmd"
)

var version = "none"

func main() {
	flag.Parse()

	infrascan := cmd.NewInfrascan(version)
	infrascan.InitRootCommand()
	infrascan.InitDiscoverCommand()

	if err := infrascan.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
