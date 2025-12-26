//go:build darwin && !cgo

// Package waps handles wireless access point discovery.
package waps

import (
	"context"
	"fmt"

	"github.com/Method-Security/infrascan/generated/go/discover"
)

// scanDarwin is a stub when CGO is not available.
// CoreWLAN requires CGO for programmatic access on macOS.
func scanDarwin(_ context.Context, _ string, _ int) ([]*discover.PassiveWirelessObservation, []int, error) {
	return nil, nil, fmt.Errorf("darwin scanning requires CGO; rebuild with CGO_ENABLED=1")
}
