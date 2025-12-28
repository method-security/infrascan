package utils

import (
	"os"
	"path/filepath"
)

// ConfigFileResolver handles resolving paths to configuration files.
type ConfigFileResolver struct {
	basePath string
}

// NewConfigFileResolver creates a new ConfigFileResolver with the given base path.
func NewConfigFileResolver(basePath string) *ConfigFileResolver {
	return &ConfigFileResolver{basePath: basePath}
}

// GetConfigFilePath returns the absolute path to a configuration file.
func (r *ConfigFileResolver) GetConfigFilePath(relativeSelection string) string {
	return filepath.Join(r.basePath, relativeSelection)
}

// GetDefaultConfigFileResolver returns a ConfigFileResolver configured for the environment.
func GetDefaultConfigFileResolver() *ConfigFileResolver {
	// In container, configs are mounted at /opt/method/infrascan/var/conf/
	containerPath := "/opt/method/infrascan/var/conf"
	if _, err := os.Stat(containerPath); err == nil {
		return NewConfigFileResolver(containerPath)
	}

	// For local development, check for a configs directory in the current working directory
	if _, err := os.Stat("configs"); err == nil {
		return NewConfigFileResolver("configs")
	}

	// Fallback to current directory
	return NewConfigFileResolver(".")
}
