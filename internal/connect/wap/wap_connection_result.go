package wap

import (
	"github.com/Method-Security/infrascan/generated/go/connect"
)

// ConnectionResult holds the result of a connection attempt.
// This is populated by platform-specific code.
type ConnectionResult struct {
	Outcome                  connect.ConnectionOutcome
	AssociationStatusCode    *connect.AssociationStatusCode
	AssociationStatusCodeRaw *int
	DeauthReasonCode         *connect.DeauthReasonCode
	DeauthReasonCodeRaw      *int
	HandshakeProgress        *connect.HandshakeProgress
	Timing                   *connect.ConnectionTiming
	RetryCount               *int
	AttemptedSecurity        *connect.NegotiatedSecurity
	NegotiatedSecurity       *connect.NegotiatedSecurity
	IPAcquired               *bool
	IPAddress                *string
	DhcpServer               *string
	Gateway                  *string
	DNSServers               []string
	PortalDetected           *bool
	PortalURL                *string
	EapMethodNegotiated      *connect.EapMethod
	ErrorMessage             *string
	PlatformConnectivity     *connect.PlatformConnectivityResult
}

// NewConnectionResult creates a new ConnectionResult with default values.
func NewConnectionResult() *ConnectionResult {
	return &ConnectionResult{
		Outcome: connect.ConnectionOutcomeUnknownError,
	}
}

// WithSuccess sets the result as successful.
func (r *ConnectionResult) WithSuccess() *ConnectionResult {
	r.Outcome = connect.ConnectionOutcomeSuccess
	return r
}

// WithAuthFailed sets the result as authentication failed.
func (r *ConnectionResult) WithAuthFailed(msg string) *ConnectionResult {
	r.Outcome = connect.ConnectionOutcomeAuthFailed
	r.ErrorMessage = &msg
	return r
}

// WithTimeout sets the result as timed out.
func (r *ConnectionResult) WithTimeout(msg string) *ConnectionResult {
	r.Outcome = connect.ConnectionOutcomeTimeout
	r.ErrorMessage = &msg
	return r
}

// WithError sets the result with a generic error.
func (r *ConnectionResult) WithError(outcome connect.ConnectionOutcome, msg string) *ConnectionResult {
	r.Outcome = outcome
	r.ErrorMessage = &msg
	return r
}
