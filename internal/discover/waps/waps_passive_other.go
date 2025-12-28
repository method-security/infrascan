//go:build !linux

package waps

import (
	"context"
	"fmt"
	"runtime"

	"github.com/Method-Security/infrascan/generated/go/discover"
)

// scanPassiveLinux is a stub for non-Linux platforms.
func scanPassiveLinux(ctx context.Context, interfaceName string, timeout int, channels []int) ([]*discover.WirelessObservation, []int, error) {
	return nil, nil, fmt.Errorf("passive scanning is only supported on Linux, not %s", runtime.GOOS)
}

// checkPassiveModeLinux is a stub for non-Linux platforms.
func checkPassiveModeLinux(ctx context.Context, interfaceName string) error {
	return fmt.Errorf("passive scanning is only supported on Linux. "+
		"On %s, true passive scanning is not possible due to OS/driver limitations", runtime.GOOS)
}
