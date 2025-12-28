// Package configs provides embedded configuration files for the infrascan binary.
// This ensures all required config files are bundled into the binary and don't
// need to be distributed separately.
package configs

import (
	"embed"
)

// EmbeddedConfigs contains all configuration files embedded in the binary.
// The directory structure is preserved, so files can be accessed via their
// relative paths (e.g., "discover/waps/oui_database.json").
//
//go:embed discover/waps/oui_database.json
var EmbeddedConfigs embed.FS

