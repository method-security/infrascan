//go:build linux

package waps

import (
	"context"
	"fmt"

	"github.com/Method-Security/infrascan/generated/go/discover"
)

// scanDarwin is a stub for linux platform - macOS scanning not available.
func scanDarwin(_ context.Context, _ string, _ int) ([]*discover.WirelessObservation, []int, error) {
	return nil, nil, fmt.Errorf("darwin scanning not available on linux; use linux scanner")
}

// scanWindows is a stub for linux platform - Windows scanning not available.
func scanWindows(_ context.Context, _ string, _ int) ([]*discover.WirelessObservation, []int, error) {
	return nil, nil, fmt.Errorf("windows scanning not available on linux; use linux scanner")
}
