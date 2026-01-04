//go:build darwin && cgo

package wap

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreWLAN -framework Foundation -framework SystemConfiguration

#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <stdlib.h>

// Connection result structure
typedef struct {
    int success;
    char* error;
    char* ssid;
    char* bssid;
    int rssi;
    int security;
} CWConnectionResult;

// Current connection info
typedef struct {
    char* ssid;
    char* bssid;
    int connected;
} CWCurrentConnection;

// Free connection result memory
void freeConnectionResult(CWConnectionResult* result) {
    if (result->error != NULL) {
        free(result->error);
        result->error = NULL;
    }
    if (result->ssid != NULL) {
        free(result->ssid);
        result->ssid = NULL;
    }
    if (result->bssid != NULL) {
        free(result->bssid);
        result->bssid = NULL;
    }
}

// Free current connection memory
void freeCurrentConnection(CWCurrentConnection* conn) {
    if (conn->ssid != NULL) {
        free(conn->ssid);
        conn->ssid = NULL;
    }
    if (conn->bssid != NULL) {
        free(conn->bssid);
        conn->bssid = NULL;
    }
}

// Helper to copy NSString to C string
char* copyNSStringToCString(NSString* str) {
    if (str == nil) return NULL;
    const char* utf8 = [str UTF8String];
    if (utf8 == NULL) return NULL;
    return strdup(utf8);
}

// Get current WiFi connection
CWCurrentConnection getCurrentWiFiConnection(char* interfaceName) {
    CWCurrentConnection result = {0};

    @autoreleasepool {
        CWWiFiClient* client = [CWWiFiClient sharedWiFiClient];
        if (client == nil) {
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
            return result;
        }

        NSString* ssid = [iface ssid];
        NSString* bssid = [iface bssid];

        if (ssid != nil && bssid != nil) {
            result.connected = 1;
            result.ssid = copyNSStringToCString(ssid);
            result.bssid = copyNSStringToCString(bssid);
        }
    }

    return result;
}

// Get signal strength for a specific network
int getNetworkSignalStrength(char* interfaceName, char* targetSSID, char* targetBSSID) {
    @autoreleasepool {
        CWWiFiClient* client = [CWWiFiClient sharedWiFiClient];
        if (client == nil) return 0;

        CWInterface* iface = nil;
        if (interfaceName != NULL) {
            NSString* ifName = [NSString stringWithUTF8String:interfaceName];
            iface = [client interfaceWithName:ifName];
        } else {
            iface = [client interface];
        }

        if (iface == nil) return 0;

        // If we're connected to this network, get current RSSI
        NSString* currentSSID = [iface ssid];
        if (targetSSID != NULL && currentSSID != nil) {
            NSString* target = [NSString stringWithUTF8String:targetSSID];
            if ([currentSSID isEqualToString:target]) {
                return (int)[iface rssiValue];
            }
        }

        // Otherwise scan for the network
        NSError* scanError = nil;
        NSSet<CWNetwork*>* networks = [iface scanForNetworksWithName:nil error:&scanError];

        if (networks == nil) return 0;

        for (CWNetwork* network in networks) {
            if (targetSSID != NULL) {
                NSString* target = [NSString stringWithUTF8String:targetSSID];
                if ([[network ssid] isEqualToString:target]) {
                    return (int)[network rssiValue];
                }
            }
            if (targetBSSID != NULL) {
                NSString* target = [NSString stringWithUTF8String:targetBSSID];
                if ([[network bssid] isEqualToString:target]) {
                    return (int)[network rssiValue];
                }
            }
        }
    }

    return 0;
}

// Disconnect from current network
int disconnectWiFi(char* interfaceName) {
    @autoreleasepool {
        CWWiFiClient* client = [CWWiFiClient sharedWiFiClient];
        if (client == nil) return -1;

        CWInterface* iface = nil;
        if (interfaceName != NULL) {
            NSString* ifName = [NSString stringWithUTF8String:interfaceName];
            iface = [client interfaceWithName:ifName];
        } else {
            iface = [client interface];
        }

        if (iface == nil) return -1;

        [iface disassociate];
        return 0;
    }
}

// Connect to an open network
CWConnectionResult connectToOpenNetwork(char* interfaceName, char* ssid) {
    CWConnectionResult result = {0};

    @autoreleasepool {
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

        // Scan for the target network
        NSString* targetSSID = [NSString stringWithUTF8String:ssid];
        NSError* scanError = nil;
        NSSet<CWNetwork*>* networks = [iface scanForNetworksWithSSID:[targetSSID dataUsingEncoding:NSUTF8StringEncoding]
                                                          error:&scanError];

        if (scanError != nil || networks == nil || [networks count] == 0) {
            result.error = strdup("Network not found");
            return result;
        }

        // Get the first matching network
        CWNetwork* network = [networks anyObject];

        // Connect without password (open network)
        NSError* connectError = nil;
        BOOL connected = [iface associateToNetwork:network password:nil error:&connectError];

        if (!connected || connectError != nil) {
            if (connectError != nil) {
                result.error = copyNSStringToCString([connectError localizedDescription]);
            } else {
                result.error = strdup("Association failed");
            }
            return result;
        }

        result.success = 1;
        result.ssid = copyNSStringToCString([network ssid]);
        result.bssid = copyNSStringToCString([network bssid]);
        result.rssi = (int)[network rssiValue];
    }

    return result;
}

// Connect to a WPA-Personal network with PSK
CWConnectionResult connectWithPSK(char* interfaceName, char* ssid, char* password) {
    CWConnectionResult result = {0};

    @autoreleasepool {
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

        // Scan for the target network
        NSString* targetSSID = [NSString stringWithUTF8String:ssid];
        NSError* scanError = nil;
        NSSet<CWNetwork*>* networks = [iface scanForNetworksWithSSID:[targetSSID dataUsingEncoding:NSUTF8StringEncoding]
                                                          error:&scanError];

        if (scanError != nil || networks == nil || [networks count] == 0) {
            result.error = strdup("Network not found");
            return result;
        }

        // Get the first matching network
        CWNetwork* network = [networks anyObject];

        // Connect with password
        NSString* pwd = [NSString stringWithUTF8String:password];
        NSError* connectError = nil;
        BOOL connected = [iface associateToNetwork:network password:pwd error:&connectError];

        if (!connected || connectError != nil) {
            if (connectError != nil) {
                NSInteger code = [connectError code];
                if (code == -3924 || code == -3930) { // Authentication failures
                    result.error = strdup("Authentication failed - incorrect password");
                } else {
                    result.error = copyNSStringToCString([connectError localizedDescription]);
                }
            } else {
                result.error = strdup("Association failed");
            }
            return result;
        }

        result.success = 1;
        result.ssid = copyNSStringToCString([network ssid]);
        result.bssid = copyNSStringToCString([network bssid]);
        result.rssi = (int)[network rssiValue];

        // Get security type
        CWSecurity security = kCWSecurityNone;
        if ([network supportsSecurity:kCWSecurityWPA3Personal]) {
            result.security = 3;
        } else if ([network supportsSecurity:kCWSecurityWPA2Personal]) {
            result.security = 2;
        } else if ([network supportsSecurity:kCWSecurityWPAPersonal]) {
            result.security = 1;
        }
    }

    return result;
}

// Find default wireless interface
char* findDefaultWirelessInterface() {
    @autoreleasepool {
        CWWiFiClient* client = [CWWiFiClient sharedWiFiClient];
        if (client == nil) return NULL;

        CWInterface* iface = [client interface];
        if (iface == nil) return NULL;

        NSString* name = [iface interfaceName];
        if (name == nil) return NULL;

        return copyNSStringToCString(name);
    }
}

// Network info for scan results
typedef struct {
    char* ssid;
    char* bssid;
    int rssi;
    int security;
} CWNetworkInfo;

// Scan result containing array of networks
typedef struct {
    CWNetworkInfo* networks;
    int count;
} CWScanResult;

// Free scan result memory
void freeScanResult(CWScanResult* result) {
    if (result->networks != NULL) {
        for (int i = 0; i < result->count; i++) {
            if (result->networks[i].ssid != NULL) {
                free(result->networks[i].ssid);
            }
            if (result->networks[i].bssid != NULL) {
                free(result->networks[i].bssid);
            }
        }
        free(result->networks);
        result->networks = NULL;
    }
    result->count = 0;
}

// Scan for available networks
CWScanResult scanNetworks(char* interfaceName) {
    CWScanResult result = {0};

    @autoreleasepool {
        CWWiFiClient* client = [CWWiFiClient sharedWiFiClient];
        if (client == nil) {
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
            return result;
        }

        NSError* scanError = nil;
        NSSet<CWNetwork*>* networks = [iface scanForNetworksWithName:nil error:&scanError];

        if (networks == nil || [networks count] == 0) {
            return result;
        }

        int count = (int)[networks count];
        result.networks = (CWNetworkInfo*)malloc(count * sizeof(CWNetworkInfo));
        if (result.networks == NULL) {
            return result;
        }

        int i = 0;
        for (CWNetwork* network in networks) {
            result.networks[i].ssid = copyNSStringToCString([network ssid]);
            result.networks[i].bssid = copyNSStringToCString([network bssid]);
            result.networks[i].rssi = (int)[network rssiValue];

            // Map security
            result.networks[i].security = 0; // Default to open
            if ([network supportsSecurity:kCWSecurityWPA3Personal] ||
                [network supportsSecurity:kCWSecurityWPA3Enterprise] ||
                [network supportsSecurity:kCWSecurityWPA3Transition]) {
                result.networks[i].security = 11; // WPA3
            } else if ([network supportsSecurity:kCWSecurityWPA2Enterprise]) {
                result.networks[i].security = 9; // WPA2 Enterprise
            } else if ([network supportsSecurity:kCWSecurityWPAEnterprise]) {
                result.networks[i].security = 7; // WPA Enterprise
            } else if ([network supportsSecurity:kCWSecurityWPA2Personal]) {
                result.networks[i].security = 4; // WPA2 Personal
            } else if ([network supportsSecurity:kCWSecurityWPAPersonal]) {
                result.networks[i].security = 2; // WPA Personal
            } else if ([network supportsSecurity:kCWSecurityWEP]) {
                result.networks[i].security = 1; // WEP
            }

            i++;
        }
        result.count = i;
    }

    return result;
}
*/
import "C"

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unsafe"

	"github.com/Method-Security/infrascan/generated/go/common"
	"github.com/Method-Security/infrascan/generated/go/connect"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// findWirelessInterface finds the default wireless interface on macOS.
func findWirelessInterface(ctx context.Context) (string, error) {
	cName := C.findDefaultWirelessInterface()
	if cName == nil {
		return "", fmt.Errorf("no wireless interface found")
	}
	defer C.free(unsafe.Pointer(cName))
	return C.GoString(cName), nil
}

// getCurrentConnection returns the current WiFi connection info.
// getConnectionProfileName returns the network profile name on macOS.
// On macOS, there's no separate "profile" concept like NetworkManager;
// connections use Keychain for credentials. Returns SSID for compatibility.
func getConnectionProfileName(ctx context.Context, interfaceName string) string {
	ssid, _, connected := getCurrentConnection(ctx, interfaceName)
	if connected {
		return ssid
	}
	return ""
}

func getCurrentConnection(ctx context.Context, interfaceName string) (ssid string, bssid string, connected bool) {
	var cInterface *C.char
	if interfaceName != "" {
		cInterface = C.CString(interfaceName)
		defer C.free(unsafe.Pointer(cInterface))
	}

	result := C.getCurrentWiFiConnection(cInterface)
	defer C.freeCurrentConnection(&result)

	if result.connected == 0 {
		return "", "", false
	}

	if result.ssid != nil {
		ssid = C.GoString(result.ssid)
	}
	if result.bssid != nil {
		bssid = C.GoString(result.bssid)
	}

	return ssid, bssid, true
}

// getSignalQuality returns the RSSI for a target network.
func getSignalQuality(ctx context.Context, interfaceName string, targetSSID string, targetBSSID string) int {
	var cInterface, cSSID, cBSSID *C.char

	if interfaceName != "" {
		cInterface = C.CString(interfaceName)
		defer C.free(unsafe.Pointer(cInterface))
	}
	if targetSSID != "" {
		cSSID = C.CString(targetSSID)
		defer C.free(unsafe.Pointer(cSSID))
	}
	if targetBSSID != "" {
		cBSSID = C.CString(targetBSSID)
		defer C.free(unsafe.Pointer(cBSSID))
	}

	return int(C.getNetworkSignalStrength(cInterface, cSSID, cBSSID))
}

// disconnectFromNetwork disconnects from the current WiFi network.
func disconnectFromNetwork(ctx context.Context, interfaceName string) error {
	var cInterface *C.char
	if interfaceName != "" {
		cInterface = C.CString(interfaceName)
		defer C.free(unsafe.Pointer(cInterface))
	}

	result := C.disconnectWiFi(cInterface)
	if result != 0 {
		return fmt.Errorf("failed to disconnect")
	}
	return nil
}

// reconnectToOriginalNetwork reconnects to the original WiFi network.
func reconnectToOriginalNetwork(ctx context.Context, interfaceName string, original *connect.OriginalNetworkState) error {
	if original == nil || !original.WasConnected {
		return nil
	}

	log := svc1log.FromContext(ctx)

	ssid := ""
	if original.Ssid != nil {
		ssid = *original.Ssid
	}

	if ssid == "" {
		return fmt.Errorf("original network SSID not available")
	}

	log.Info("Attempting to reconnect to original network",
		svc1log.SafeParam("ssid", ssid))

	// On macOS, reconnecting to a known network should work automatically
	// if it's in the preferred networks list. Try open connection first.
	var cInterface *C.char
	if interfaceName != "" {
		cInterface = C.CString(interfaceName)
		defer C.free(unsafe.Pointer(cInterface))
	}

	cSSID := C.CString(ssid)
	defer C.free(unsafe.Pointer(cSSID))

	// Try connecting as open network (macOS will use saved credentials)
	result := C.connectToOpenNetwork(cInterface, cSSID)
	defer C.freeConnectionResult(&result)

	if result.success != 0 {
		// Wait for connection to stabilize and verify
		time.Sleep(2 * time.Second)

		// Verify we're connected
		currentSSID, _, connected := getCurrentConnection(ctx, interfaceName)
		if connected && currentSSID == ssid {
			return nil
		}
	}

	// If open connection failed, the network might need credentials
	// macOS should auto-connect using Keychain credentials
	// Give it some time and check again
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		currentSSID, _, connected := getCurrentConnection(ctx, interfaceName)
		if connected && currentSSID == ssid {
			return nil
		}
	}

	return fmt.Errorf("failed to reconnect to original network after 10 seconds")
}

// connectToNetwork performs the actual connection attempt.
func connectToNetwork(
	ctx context.Context,
	interfaceName string,
	targetSSID string,
	targetBSSID string,
	cred *connect.TestClientProfile,
	timeout int,
) *ConnectionResult {
	log := svc1log.FromContext(ctx)
	result := NewConnectionResult()

	var cInterface *C.char
	if interfaceName != "" {
		cInterface = C.CString(interfaceName)
		defer C.free(unsafe.Pointer(cInterface))
	}

	cSSID := C.CString(targetSSID)
	defer C.free(unsafe.Pointer(cSSID))

	var cwResult C.CWConnectionResult

	switch cred.CredentialType {
	case connect.TestCredentialTypeNone:
		// Open network connection
		cwResult = C.connectToOpenNetwork(cInterface, cSSID)
		defer C.freeConnectionResult(&cwResult)

	case connect.TestCredentialTypePskSimple, connect.TestCredentialTypePskCommon:
		// PSK connection
		if cred.Psk == nil || *cred.Psk == "" {
			result.WithError(connect.ConnectionOutcomeAuthFailed, "PSK credential required but not provided")
			return result
		}
		cPassword := C.CString(*cred.Psk)
		defer C.free(unsafe.Pointer(cPassword))

		cwResult = C.connectWithPSK(cInterface, cSSID, cPassword)
		defer C.freeConnectionResult(&cwResult)

	case connect.TestCredentialTypeEapTestIdentity, connect.TestCredentialTypeEapGuest:
		// EAP connection - not directly supported via CoreWLAN
		// Would need to use profiles or networksetup command
		log.Warn("EAP credentials not directly supported on macOS via CoreWLAN")
		result.WithError(connect.ConnectionOutcomeAuthFailed, "EAP authentication not supported via direct API on macOS")
		return result

	default:
		result.WithError(connect.ConnectionOutcomeUnknownError, fmt.Sprintf("unsupported credential type: %s", cred.CredentialType))
		return result
	}

	// Process result
	if cwResult.success != 0 {
		result.WithSuccess()

		// Set negotiated security info
		if cwResult.security > 0 {
			negSec := &connect.NegotiatedSecurity{}
			switch cwResult.security {
			case 3:
				wpaVer := common.WpaVersionWpa3
				negSec.WpaVersion = (*common.WpaVersion)(&wpaVer)
				authMethod := common.AuthenticationMethodSae
				negSec.AuthenticationMethod = (*common.AuthenticationMethod)(&authMethod)
			case 2:
				wpaVer := common.WpaVersionWpa2
				negSec.WpaVersion = (*common.WpaVersion)(&wpaVer)
			case 1:
				wpaVer := common.WpaVersionWpa1
				negSec.WpaVersion = (*common.WpaVersion)(&wpaVer)
			}
			result.NegotiatedSecurity = negSec
		}

		// Check for IP and DHCP
		ipAcquired, ipAddr, gateway, dnsServers := waitForDHCP(ctx, interfaceName, timeout)
		result.IpAcquired = &ipAcquired
		if ipAddr != "" {
			result.IpAddress = &ipAddr
		}
		if gateway != "" {
			result.Gateway = &gateway
		}
		if len(dnsServers) > 0 {
			result.DnsServers = dnsServers
		}

		// Check for captive portal
		if ipAcquired {
			portalDetected, portalURL := detectCaptivePortal(ctx)
			result.PortalDetected = &portalDetected
			if portalURL != "" {
				result.PortalUrl = &portalURL
			}
		}
	} else {
		// Connection failed
		errMsg := "Connection failed"
		if cwResult.error != nil {
			errMsg = C.GoString(cwResult.error)
		}

		// Determine outcome based on error
		if strings.Contains(errMsg, "not found") {
			result.WithError(connect.ConnectionOutcomeNetworkNotFound, errMsg)
		} else if strings.Contains(errMsg, "Authentication") || strings.Contains(errMsg, "password") {
			result.WithError(connect.ConnectionOutcomeAuthFailed, errMsg)
		} else {
			result.WithError(connect.ConnectionOutcomeAssocFailed, errMsg)
		}
	}

	return result
}

// waitForDHCP waits for DHCP to assign an IP address.
func waitForDHCP(ctx context.Context, interfaceName string, timeout int) (acquired bool, ip string, gateway string, dns []string) {
	log := svc1log.FromContext(ctx)
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)

	for time.Now().Before(deadline) {
		// Get IP using ifconfig (simple approach)
		ip, gateway, dns = getNetworkInfo(interfaceName)
		if ip != "" && !strings.HasPrefix(ip, "169.254.") { // Not a link-local address
			log.Info("DHCP lease acquired",
				svc1log.SafeParam("ip", ip),
				svc1log.SafeParam("gateway", gateway))
			return true, ip, gateway, dns
		}
		time.Sleep(1 * time.Second)
	}

	log.Warn("DHCP timeout - no IP acquired")
	return false, "", "", nil
}

// getNetworkInfo retrieves IP, gateway, and DNS info for an interface.
func getNetworkInfo(interfaceName string) (ip string, gateway string, dns []string) {
	// This is a simplified implementation
	// A full implementation would use SCDynamicStore or parse ifconfig output
	// For now, we return empty values and let the caller handle it
	return "", "", nil
}

// detectCaptivePortal checks if there's a captive portal on the network.
func detectCaptivePortal(ctx context.Context) (detected bool, portalURL string) {
	log := svc1log.FromContext(ctx)

	// Use Apple's captive portal detection URL
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Stop following redirects to detect portal
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get("http://captive.apple.com/hotspot-detect.html")
	if err != nil {
		log.Debug("Captive portal check failed", svc1log.SafeParam("error", err.Error()))
		return false, ""
	}
	defer resp.Body.Close()

	// If we get a redirect, there's a captive portal
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		return true, location
	}

	// Check response body - Apple's page returns "Success" if no portal
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Success") {
		return true, ""
	}

	return false, ""
}

// detectNetworkSecurity detects the security type of a target wireless network on macOS.
// Uses CoreWLAN to scan for the network and determine its security configuration.
func detectNetworkSecurity(ctx context.Context, interfaceName string, targetSSID string, targetBSSID string) NetworkSecurityType {
	log := svc1log.FromContext(ctx)

	var cInterface *C.char
	if interfaceName != "" {
		cInterface = C.CString(interfaceName)
		defer C.free(unsafe.Pointer(cInterface))
	}

	// Scan for networks
	var scanResult C.CWScanResult
	scanResult = C.scanNetworks(cInterface)
	defer C.freeScanResult(&scanResult)

	if scanResult.count == 0 {
		log.Warn("No networks found during security detection scan")
		return NetworkSecurityUnknown
	}

	// Parse scan results to find target network
	for i := C.int(0); i < scanResult.count; i++ {
		network := scanResult.networks[i]
		ssid := C.GoString(network.ssid)
		bssid := strings.ToUpper(C.GoString(network.bssid))

		// Match by SSID or BSSID
		matchSSID := targetSSID != "" && ssid == targetSSID
		matchBSSID := targetBSSID != "" && strings.EqualFold(bssid, targetBSSID)

		if matchSSID || matchBSSID {
			// Map security value from CoreWLAN
			// CWSecurity enum values (from Apple documentation):
			// 0 = None/Open, 1 = WEP, 2 = WPA Personal, 3 = WPA Personal Mixed,
			// 4 = WPA2 Personal, 5 = Personal, 6 = Dynamic WEP, 7 = WPA Enterprise,
			// 8 = WPA Enterprise Mixed, 9 = WPA2 Enterprise, 10 = Enterprise,
			// 11 = WPA3 Personal, 12 = WPA3 Enterprise, 13 = WPA3 Transition
			security := int(network.security)
			log.Debug("Found target network security",
				svc1log.SafeParam("ssid", ssid),
				svc1log.SafeParam("security_value", security))

			switch security {
			case 0: // Open
				return NetworkSecurityOpen
			case 1: // WEP
				return NetworkSecurityPSK
			case 2, 3, 4, 5, 11, 13: // WPA/WPA2/WPA3 Personal variants
				return NetworkSecurityPSK
			case 6, 7, 8, 9, 10, 12: // Enterprise variants
				return NetworkSecurityEAP
			default:
				log.Warn("Unknown security type from CoreWLAN",
					svc1log.SafeParam("security_value", security))
				return NetworkSecurityUnknown
			}
		}
	}

	log.Warn("Target network not found in scan results",
		svc1log.SafeParam("target_ssid", targetSSID),
		svc1log.SafeParam("target_bssid", targetBSSID))
	return NetworkSecurityUnknown
}

