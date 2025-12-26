package waps

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/Method-Security/infrascan/utils"
)

var (
	ouiDatabase     map[string]string
	ouiDatabaseLock sync.RWMutex
)

// lookupOUI returns the vendor name for a given OUI (first 3 bytes of MAC address).
func lookupOUI(oui string) *string {
	// Normalize OUI format (uppercase, colon-separated)
	oui = normalizeOUI(oui)

	db, err := getOUIDatabase()
	if err != nil {
		return nil
	}

	if vendor, ok := db[oui]; ok {
		return &vendor
	}
	return nil
}

// getOUIDatabase loads and caches the OUI database
func getOUIDatabase() (map[string]string, error) {
	ouiDatabaseLock.RLock()
	if ouiDatabase != nil {
		defer ouiDatabaseLock.RUnlock()
		return ouiDatabase, nil
	}
	ouiDatabaseLock.RUnlock()

	ouiDatabaseLock.Lock()
	defer ouiDatabaseLock.Unlock()

	if ouiDatabase != nil {
		return ouiDatabase, nil
	}

	resolver := utils.GetDefaultConfigFileResolver()
	filePath := resolver.GetConfigFilePath("discover/waps/oui_database.json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read OUI database: %w", err)
	}

	var db map[string]string
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to parse OUI database: %w", err)
	}

	ouiDatabase = db
	return ouiDatabase, nil
}

// normalizeOUI converts an OUI to uppercase colon-separated format.
func normalizeOUI(oui string) string {
	// Already in correct format if 8 chars with colons
	if len(oui) == 8 {
		result := make([]byte, 8)
		for i, c := range oui {
			if c >= 'a' && c <= 'z' {
				result[i] = byte(c - 32) // Convert to uppercase
			} else {
				result[i] = byte(c)
			}
		}
		return string(result)
	}
	return oui
}
