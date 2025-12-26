//go:build windows

package waps

import (
	"context"
	"fmt"

	"github.com/Method-Security/infrascan/generated/go/discover"
)

// scanDarwin is a stub for windows platform - macOS scanning not available.
func scanDarwin(_ context.Context, _ string, _ int) ([]*discover.PassiveWirelessObservation, []int, error) {
	return nil, nil, fmt.Errorf("darwin scanning not available on windows; use windows scanner")
}

// scanLinux is a stub for windows platform - Linux scanning not available.
func scanLinux(_ context.Context, _ string, _ int) ([]*discover.PassiveWirelessObservation, []int, error) {
	return nil, nil, fmt.Errorf("linux scanning not available on windows; use windows scanner")
}
