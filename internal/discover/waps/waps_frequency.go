//go:build linux || windows

// Package waps handles wireless access point discovery.
package waps

import (
	common "github.com/Method-Security/infrascan/generated/go/common"
)

// determineFrequencyBand returns the frequency band based on channel number.
// This is used by Linux and Windows scanners which don't have native band detection.
// Darwin uses CoreWLAN's native band values instead.
func determineFrequencyBand(channel int) *common.FrequencyBand {
	var band common.FrequencyBand
	switch {
	case channel >= 1 && channel <= 14:
		band = common.FrequencyBandBand24Ghz
	case channel >= 32 && channel <= 177:
		band = common.FrequencyBandBand5Ghz
	case channel >= 1 && channel <= 233: // 6GHz channels overlap numbering
		// This is a simplification; proper detection needs frequency info
		band = common.FrequencyBandBandUnknown
	default:
		band = common.FrequencyBandBandUnknown
	}
	return &band
}
