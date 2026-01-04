package wap

import "github.com/Method-Security/infrascan/generated/go/associate"

// ConnectionResult holds the result of a connection attempt.
// This is populated by platform-specific code.
type ConnectionResult struct {
	Outcome            associate.AssociationOutcome
	StatusCode         *associate.AssociationStatusCode
	StatusCodeRaw      *int
	ReasonCode         *associate.DeauthReasonCode
	ReasonCodeRaw      *int
	HandshakeProgress  *associate.HandshakeProgress
	Timing             *associate.AssociationTiming
	RetryCount         *int
	AttemptedSecurity  *associate.NegotiatedSecurity
	NegotiatedSecurity *associate.NegotiatedSecurity
	IpAcquired         *bool
	IpAddress          *string
	DhcpServer         *string
	Gateway            *string
	DnsServers         []string
	PortalDetected     *bool
	PortalUrl          *string
	EapMethodNegotiated *associate.EapMethod
	ErrorMessage       *string
	PlatformConnectivity *associate.PlatformConnectivityResult
}

// NewConnectionResult creates a new ConnectionResult with default values.
func NewConnectionResult() *ConnectionResult {
	return &ConnectionResult{
		Outcome: associate.AssociationOutcomeUnknownError,
	}
}

// WithSuccess sets the result as successful.
func (r *ConnectionResult) WithSuccess() *ConnectionResult {
	r.Outcome = associate.AssociationOutcomeSuccess
	return r
}

// WithAuthFailed sets the result as authentication failed.
func (r *ConnectionResult) WithAuthFailed(msg string) *ConnectionResult {
	r.Outcome = associate.AssociationOutcomeAuthFailed
	r.ErrorMessage = &msg
	return r
}

// WithTimeout sets the result as timed out.
func (r *ConnectionResult) WithTimeout(msg string) *ConnectionResult {
	r.Outcome = associate.AssociationOutcomeTimeout
	r.ErrorMessage = &msg
	return r
}

// WithError sets the result with a generic error.
func (r *ConnectionResult) WithError(outcome associate.AssociationOutcome, msg string) *ConnectionResult {
	r.Outcome = outcome
	r.ErrorMessage = &msg
	return r
}

