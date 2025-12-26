//go:build !darwin && !linux && !windows

package waps

import (
	"context"
	"fmt"
	"runtime"

	"github.com/Method-Security/infrascan/generated/go/discover"
)

// scanDarwin is a stub for unsupported platforms.
func scanDarwin(_ context.Context, _ string, _ int) ([]*discover.PassiveWirelessObservation, []int, error) {
	return nil, nil, fmt.Errorf("wireless scanning not supported on %s", runtime.GOOS)
}

// scanLinux is a stub for unsupported platforms.
func scanLinux(_ context.Context, _ string, _ int) ([]*discover.PassiveWirelessObservation, []int, error) {
	return nil, nil, fmt.Errorf("wireless scanning not supported on %s", runtime.GOOS)
}

// scanWindows is a stub for unsupported platforms.
func scanWindows(_ context.Context, _ string, _ int) ([]*discover.PassiveWirelessObservation, []int, error) {
	return nil, nil, fmt.Errorf("wireless scanning not supported on %s", runtime.GOOS)
}
