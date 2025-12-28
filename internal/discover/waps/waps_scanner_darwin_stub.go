//go:build darwin

package waps

import (
	"context"
	"fmt"

	"github.com/Method-Security/infrascan/generated/go/discover"
)

// scanLinux is a stub for darwin platform - Linux scanning not available.
func scanLinux(_ context.Context, _ string, _ int) ([]*discover.WirelessObservation, []int, error) {
	return nil, nil, fmt.Errorf("linux scanning not available on darwin; use darwin scanner")
}

// scanWindows is a stub for darwin platform - Windows scanning not available.
func scanWindows(_ context.Context, _ string, _ int) ([]*discover.WirelessObservation, []int, error) {
	return nil, nil, fmt.Errorf("windows scanning not available on darwin; use darwin scanner")
}
