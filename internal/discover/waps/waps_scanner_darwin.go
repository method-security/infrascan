//go:build darwin && cgo

package waps

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreWLAN -framework Foundation -framework CoreLocation

#import <CoreWLAN/CoreWLAN.h>
#import <CoreLocation/CoreLocation.h>
#include <stdlib.h>

// Network info structure
typedef struct {
    char* bssid;
    char* ssid;
    int channel;
    int channelBand;
    int channelWidth;
    int rssi;
    int noise;
    int wep;
    int wpa;
    int wpa2;
    int wpa3;
    int enterprise;
} CWNetworkInfo;

// Scan result structure
typedef struct {
    CWNetworkInfo* networks;
    int count;
    char* error;
    char* interfaceName;
} CWScanResult;

// Free memory allocated for scan result
void freeScanResult(CWScanResult* result) {
    if (result->networks != NULL) {
        for (int i = 0; i < result->count; i++) {
            free(result->networks[i].bssid);
            free(result->networks[i].ssid);
        }
        free(result->networks);
        result->networks = NULL;
    }
    if (result->error != NULL) {
        free(result->error);
        result->error = NULL;
    }
    if (result->interfaceName != NULL) {
        free(result->interfaceName);
        result->interfaceName = NULL;
    }
}

// Helper to copy NSString to C string
char* copyNSString(NSString* str) {
    if (str == nil) return NULL;
    const char* utf8 = [str UTF8String];
    if (utf8 == NULL) return NULL;
    return strdup(utf8);
}

// Convert CWNetwork to CWNetworkInfo
CWNetworkInfo convertNetwork(CWNetwork* network) {
    CWNetworkInfo info = {0};

    info.bssid = copyNSString([network bssid]);
    info.ssid = copyNSString([network ssid]);

    CWChannel* channel = [network wlanChannel];
    if (channel != nil) {
        info.channel = (int)[channel channelNumber];
        info.channelBand = (int)[channel channelBand];
        info.channelWidth = (int)[channel channelWidth];
    }

    info.rssi = (int)[network rssiValue];
    info.noise = (int)[network noiseMeasurement];

    // Check security using supportsSecurity: method (modern CoreWLAN API)
    info.wep = [network supportsSecurity:kCWSecurityWEP];
    info.wpa = [network supportsSecurity:kCWSecurityWPAPersonal] ||
               [network supportsSecurity:kCWSecurityWPAEnterprise] ||
               [network supportsSecurity:kCWSecurityWPAPersonalMixed] ||
               [network supportsSecurity:kCWSecurityWPAEnterpriseMixed];
    info.wpa2 = [network supportsSecurity:kCWSecurityWPA2Personal] ||
                [network supportsSecurity:kCWSecurityWPA2Enterprise] ||
                [network supportsSecurity:kCWSecurityWPA3Personal] ||
                [network supportsSecurity:kCWSecurityWPA3Enterprise] ||
                [network supportsSecurity:kCWSecurityWPA3Transition];
    info.wpa3 = [network supportsSecurity:kCWSecurityWPA3Personal] ||
                [network supportsSecurity:kCWSecurityWPA3Enterprise] ||
                [network supportsSecurity:kCWSecurityWPA3Transition];
    info.enterprise = [network supportsSecurity:kCWSecurityWPAEnterprise] ||
                      [network supportsSecurity:kCWSecurityWPA2Enterprise] ||
                      [network supportsSecurity:kCWSecurityWPAEnterpriseMixed] ||
                      [network supportsSecurity:kCWSecurityWPA3Enterprise];

    return info;
}

// Get the currently connected network (doesn't require Location Services)
CWScanResult getCurrentNetwork() {
    CWScanResult result = {0};

    @autoreleasepool {
        CWWiFiClient* client = [CWWiFiClient sharedWiFiClient];
        if (client == nil) {
            result.error = strdup("Failed to get WiFi client");
            return result;
        }

        CWInterface* iface = [client interface];
        if (iface == nil) {
            result.error = strdup("No WiFi interface available");
            return result;
        }

        // Get the current network we're connected to
        NSString* ssid = [iface ssid];
        NSString* bssid = [iface bssid];

        if (ssid == nil || bssid == nil) {
            // Not connected to any network
            result.count = 0;
            return result;
        }

        // Create a single network entry for current network
        result.networks = (CWNetworkInfo*)malloc(sizeof(CWNetworkInfo));
        result.count = 1;

        CWNetworkInfo* info = &result.networks[0];
        memset(info, 0, sizeof(CWNetworkInfo));

        info->bssid = copyNSString(bssid);
        info->ssid = copyNSString(ssid);

        CWChannel* channel = [iface wlanChannel];
        if (channel != nil) {
            info->channel = (int)[channel channelNumber];
            info->channelBand = (int)[channel channelBand];
            info->channelWidth = (int)[channel channelWidth];
        }

        info->rssi = (int)[iface rssiValue];
        info->noise = (int)[iface noiseMeasurement];

        // For current network, we can get security from the interface
        CWSecurity security = [iface security];
        info->wep = (security == kCWSecurityWEP);
        info->wpa = (security == kCWSecurityWPAPersonal || security == kCWSecurityWPAEnterprise);
        info->wpa2 = (security == kCWSecurityWPA2Personal || security == kCWSecurityWPA2Enterprise);
        info->wpa3 = (security == kCWSecurityWPA3Personal || security == kCWSecurityWPA3Enterprise ||
                      security == kCWSecurityWPA3Transition);
        info->enterprise = (security == kCWSecurityWPAEnterprise || security == kCWSecurityWPA2Enterprise ||
                           security == kCWSecurityWPA3Enterprise);

        result.interfaceName = copyNSString([iface interfaceName]);
    }

    return result;
}

// Perform a WiFi scan using CoreWLAN
CWScanResult scanCoreWLAN(char* interfaceName) {
    CWScanResult result = {0};

    @autoreleasepool {
        NSLog(@"[infrascan] Starting CoreWLAN scan");

        CWWiFiClient* client = [CWWiFiClient sharedWiFiClient];
        if (client == nil) {
            result.error = strdup("Failed to get WiFi client");
            return result;
        }

        CWInterface* iface = nil;
        if (interfaceName != NULL) {
            NSString* ifName = [NSString stringWithUTF8String:interfaceName];
            iface = [client interfaceWithName:ifName];
        } else {
            iface = [client interface];
        }

        if (iface == nil) {
            result.error = strdup("No WiFi interface available");
            return result;
        }

        result.interfaceName = copyNSString([iface interfaceName]);
        NSLog(@"[infrascan] Using interface: %@", [iface interfaceName]);

        // Check Location Services authorization
        CLLocationManager* locationManager = [[CLLocationManager alloc] init];
        CLAuthorizationStatus authStatus = [locationManager authorizationStatus];
        NSLog(@"[infrascan] Location authorization status: %d", (int)authStatus);

        // Perform scan
        NSError* scanError = nil;
        NSSet<CWNetwork*>* networks = [iface scanForNetworksWithName:nil error:&scanError];

        if (scanError != nil) {
            NSString* errMsg = [NSString stringWithFormat:@"Scan failed: %@ (code %ld). Location Services may need to be enabled for this app.",
                               [scanError localizedDescription], (long)[scanError code]];
            result.error = strdup([errMsg UTF8String]);
            NSLog(@"[infrascan] Scan error: %@", errMsg);
            return result;
        }

        if (networks == nil || [networks count] == 0) {
            NSLog(@"[infrascan] No networks found");
            result.count = 0;
            return result;
        }

        NSLog(@"[infrascan] Found %lu networks", (unsigned long)[networks count]);

        // Allocate array for network info
        result.count = (int)[networks count];
        result.networks = (CWNetworkInfo*)malloc(sizeof(CWNetworkInfo) * result.count);

        int i = 0;
        for (CWNetwork* network in networks) {
            result.networks[i] = convertNetwork(network);
            NSLog(@"[infrascan] Network %d: ssid=%@, bssid=%@, channel=%d, rssi=%ld",
                  i, [network ssid], [network bssid],
                  (int)[[network wlanChannel] channelNumber],
                  (long)[network rssiValue]);
            i++;
        }
    }

    return result;
}
*/
import "C"

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/Method-Security/infrascan/generated/go/common"
	"github.com/Method-Security/infrascan/generated/go/discover"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// scanDarwin performs wireless scanning on macOS using CoreWLAN.
func scanDarwin(ctx context.Context, interfaceName string, timeout int) ([]*discover.WirelessObservation, []int, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting macOS wireless scan using CoreWLAN")

	// Convert interface name to C string
	var cInterfaceName *C.char
	if interfaceName != "" {
		cInterfaceName = C.CString(interfaceName)
		defer C.free(unsafe.Pointer(cInterfaceName))
	}

	// Perform scan using CoreWLAN
	result := C.scanCoreWLAN(cInterfaceName)
	defer C.freeScanResult(&result)

	// Check for errors
	if result.error != nil {
		errStr := C.GoString(result.error)
		log.Warn("CoreWLAN scan failed, trying current network fallback",
			svc1log.SafeParam("error", errStr))

		// Try to get at least the current network (doesn't require Location Services)
		currentResult := C.getCurrentNetwork()
		defer C.freeScanResult(&currentResult)

		if currentResult.error != nil {
			return nil, nil, fmt.Errorf("%s", errStr)
		}

		if currentResult.count == 0 {
			return nil, nil, fmt.Errorf("%s (also not currently connected to any network)", errStr)
		}

		log.Info("Using current network info (full scan requires Location Services permission)")
		observations, channels := convertCWScanResult(&currentResult)
		return observations, channels, fmt.Errorf("%s; returned current network only", errStr)
	}

	if result.interfaceName != nil {
		log.Info("Scanning on interface", svc1log.SafeParam("interface", C.GoString(result.interfaceName)))
	}

	observations, channels := convertCWScanResult(&result)

	// Check if data was redacted (SSID/BSSID null but networks exist)
	redactedCount := 0
	for _, obs := range observations {
		if strings.HasPrefix(obs.Bssid, "REDACTED:") {
			redactedCount++
		}
	}

	var scanWarning error
	if redactedCount > 0 {
		log.Warn("Location Services permission incomplete - SSID/BSSID redacted by macOS",
			svc1log.SafeParam("redacted_networks", redactedCount),
			svc1log.SafeParam("total_networks", len(observations)))
		scanWarning = fmt.Errorf("Location Services permission incomplete: %d of %d networks have redacted SSID/BSSID. "+
			"Enable Location Services for the responsible app (Codex or Terminal) in System Settings > Privacy & Security > Location Services, then reopen that app and rerun the scan",
			redactedCount, len(observations))
	}

	log.Info("Completed macOS wireless scan",
		svc1log.SafeParam("aps_found", len(observations)),
		svc1log.SafeParam("channels_scanned", len(channels)))

	return observations, channels, scanWarning
}

// convertCWScanResult converts C scan results to Go observations.
func convertCWScanResult(result *C.CWScanResult) ([]*discover.WirelessObservation, []int) {
	var observations []*discover.WirelessObservation
	channelMap := make(map[int]bool)

	if result.count == 0 || result.networks == nil {
		return observations, nil
	}

	// Convert C array to Go slice
	networks := unsafe.Slice(result.networks, result.count)

	for _, network := range networks {
		obs := convertCWNetwork(&network)
		if obs != nil {
			observations = append(observations, obs)
			if obs.RadioCharacteristics != nil && obs.RadioCharacteristics.Channel != nil {
				channelMap[*obs.RadioCharacteristics.Channel] = true
			}
		}
	}

	var channels []int
	for ch := range channelMap {
		channels = append(channels, ch)
	}

	return observations, channels
}

// convertCWNetwork converts a single CWNetworkInfo to a WirelessObservation.
func convertCWNetwork(network *C.CWNetworkInfo) *discover.WirelessObservation {
	bssid := C.GoString(network.bssid)
	ssidStr := C.GoString(network.ssid)

	// If both SSID and BSSID are empty, macOS is redacting due to Location Services
	// We still have useful data (channel, RSSI, security) so create a placeholder
	if bssid == "" {
		// Generate a placeholder BSSID based on channel and RSSI for uniqueness
		channel := int(network.channel)
		rssi := int(network.rssi)
		bssid = fmt.Sprintf("REDACTED:%02d:%03d", channel, -rssi)
	}

	var ssidPtr *string
	isHidden := ssidStr == ""
	if !isHidden {
		ssidPtr = &ssidStr
	} else {
		// Mark as redacted if we have a placeholder BSSID
		if strings.HasPrefix(bssid, "REDACTED:") {
			redactedSSID := "[Location Services - SSID Redacted]"
			ssidPtr = &redactedSSID
			isHidden = false // It's not hidden, just redacted
		}
	}

	channel := int(network.channel)
	rssi := int(network.rssi)
	noise := int(network.noise)
	freq := channelToFrequency(channel)
	band := determineFrequencyBandFromCW(int(network.channelBand))
	width := determineChannelWidthFromCW(int(network.channelWidth))

	// Build security configuration
	secConfig := buildSecurityConfig(network)

	// Determine WiFi generation from channel band
	wifiGen := determineWifiGenerationFromBand(int(network.channelBand), channel)

	now := time.Now()
	passiveOnly := false // CoreWLAN scan sends probes
	beaconFrame := common.FrameTypeBeacon

	return &discover.WirelessObservation{
		Bssid:        bssid,
		Ssid:         ssidPtr,
		SsidLength:   ptr(len(ssidStr)),
		IsHiddenSsid: &isHidden,
		RadioCharacteristics: &discover.RadioCharacteristics{
			Channel:      &channel,
			FrequencyMhz: &freq,
			Band:         band,
			ChannelWidth: width,
			Rssi:         &rssi,
			NoiseFloor:   &noise,
		},
		SecurityConfiguration: secConfig,
		ProtocolCapabilities: &discover.ProtocolCapabilities{
			WifiGeneration: wifiGen,
		},
		ObservationMetadata: &discover.ObservationMetadata{
			Timestamp:   &now,
			PassiveOnly: &passiveOnly,
			FrameTypes:  []common.FrameType{beaconFrame},
		},
	}
}

// buildSecurityConfig builds security configuration from CWNetworkInfo.
func buildSecurityConfig(network *C.CWNetworkInfo) *discover.SecurityConfiguration {
	config := &discover.SecurityConfiguration{}

	hasWEP := network.wep != 0
	hasWPA := network.wpa != 0
	hasWPA2 := network.wpa2 != 0
	hasWPA3 := network.wpa3 != 0
	hasEnterprise := network.enterprise != 0

	// Check for open network
	if !hasWEP && !hasWPA && !hasWPA2 && !hasWPA3 {
		isOpen := true
		config.IsOpenNetwork = &isOpen
		auth := common.AuthenticationMethodOpen
		config.AuthenticationMethod = &auth
		enc := common.EncryptionProtocolNone
		config.EncryptionProtocol = &enc
		return config
	}

	isOpen := false
	config.IsOpenNetwork = &isOpen

	// WEP
	if hasWEP {
		wepEnabled := true
		config.IsWepEnabled = &wepEnabled
		enc := common.EncryptionProtocolWep
		config.EncryptionProtocol = &enc
		return config
	}

	// Determine WPA version
	if hasWPA3 && hasWPA2 {
		version := common.WpaVersionWpa2Wpa3Mixed
		config.WpaVersion = &version
	} else if hasWPA3 {
		version := common.WpaVersionWpa3
		config.WpaVersion = &version
	} else if hasWPA2 {
		version := common.WpaVersionWpa2
		config.WpaVersion = &version
	} else if hasWPA {
		version := common.WpaVersionWpa1
		config.WpaVersion = &version
	}

	// Set key management and auth method
	if hasEnterprise {
		auth := common.AuthenticationMethodEap
		config.AuthenticationMethod = &auth
		keyMgmt := common.KeyManagementTypeEap8021X
		config.KeyManagement = []common.KeyManagementType{keyMgmt}
	} else if hasWPA3 {
		auth := common.AuthenticationMethodSae
		config.AuthenticationMethod = &auth
		keyMgmt := common.KeyManagementTypeSae
		config.KeyManagement = []common.KeyManagementType{keyMgmt}
	} else {
		// WPA/WPA2 Personal (PSK)
		auth := common.AuthenticationMethodPsk
		config.AuthenticationMethod = &auth
		keyMgmt := common.KeyManagementTypePsk
		config.KeyManagement = []common.KeyManagementType{keyMgmt}
	}

	// Set encryption protocol (WPA2+ uses CCMP/AES)
	if hasWPA2 || hasWPA3 {
		enc := common.EncryptionProtocolCcmp
		config.EncryptionProtocol = &enc
		cipher := common.CipherSuiteCcmp128
		config.PairwiseCipherSuites = []common.CipherSuite{cipher}
	} else if hasWPA {
		enc := common.EncryptionProtocolTkip
		config.EncryptionProtocol = &enc
		cipher := common.CipherSuiteTkip
		config.PairwiseCipherSuites = []common.CipherSuite{cipher}
	}

	return config
}

// determineFrequencyBandFromCW converts CoreWLAN channel band to FrequencyBand.
// CWChannelBand values: kCWChannelBandUnknown=0, kCWChannelBand2GHz=1, kCWChannelBand5GHz=2, kCWChannelBand6GHz=3
func determineFrequencyBandFromCW(cwBand int) *common.FrequencyBand {
	var band common.FrequencyBand
	switch cwBand {
	case 1: // kCWChannelBand2GHz
		band = common.FrequencyBandBand24Ghz
	case 2: // kCWChannelBand5GHz
		band = common.FrequencyBandBand5Ghz
	case 3: // kCWChannelBand6GHz
		band = common.FrequencyBandBand6Ghz
	default:
		band = common.FrequencyBandBandUnknown
	}
	return &band
}

// determineChannelWidthFromCW converts CoreWLAN channel width to ChannelWidth.
// CWChannelWidth values: kCWChannelWidthUnknown=0, kCWChannelWidth20MHz=1, kCWChannelWidth40MHz=2,
// kCWChannelWidth80MHz=3, kCWChannelWidth160MHz=4
func determineChannelWidthFromCW(cwWidth int) *common.ChannelWidth {
	var width common.ChannelWidth
	switch cwWidth {
	case 1: // kCWChannelWidth20MHz
		width = common.ChannelWidthWidth20Mhz
	case 2: // kCWChannelWidth40MHz
		width = common.ChannelWidthWidth40Mhz
	case 3: // kCWChannelWidth80MHz
		width = common.ChannelWidthWidth80Mhz
	case 4: // kCWChannelWidth160MHz
		width = common.ChannelWidthWidth160Mhz
	default:
		width = common.ChannelWidthWidthUnknown
	}
	return &width
}

// determineWifiGenerationFromBand estimates WiFi generation based on band and channel.
func determineWifiGenerationFromBand(cwBand int, channel int) *common.WifiGeneration {
	var gen common.WifiGeneration
	switch cwBand {
	case 3: // 6 GHz - WiFi 6E minimum
		gen = common.WifiGenerationWifi6E
	case 2: // 5 GHz
		if channel >= 149 {
			gen = common.WifiGenerationWifi5 // Likely WiFi 5+
		} else {
			gen = common.WifiGenerationUnknown
		}
	case 1: // 2.4 GHz
		gen = common.WifiGenerationUnknown // Could be any generation
	default:
		gen = common.WifiGenerationUnknown
	}
	return &gen
}
