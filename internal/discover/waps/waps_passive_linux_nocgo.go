//go:build linux && !cgo

package waps

import (
	"context"
	"fmt"

	"github.com/Method-Security/infrascan/generated/go/discover"
)

// scanPassiveLinux is a stub for non-CGO builds.
// Passive scanning requires CGO for libpcap bindings.
func scanPassiveLinux(ctx context.Context, interfaceName string, timeout int, channels []int) ([]*discover.WirelessObservation, []int, error) {
	return nil, nil, fmt.Errorf("passive scanning requires CGO (libpcap). " +
		"Build with CGO_ENABLED=1 and ensure libpcap-dev is installed")
}

// checkPassiveModeLinux is a stub for non-CGO builds.
func checkPassiveModeLinux(ctx context.Context, interfaceName string) error {
	return fmt.Errorf("passive scanning requires CGO (libpcap). " +
		"Build with CGO_ENABLED=1 and ensure libpcap-dev is installed")
}
