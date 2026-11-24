//go:build darwin && cgo

#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>
#include <string.h>

size_t sohaOpenWiFiSSID(const char *name, unsigned char *out) {
    @autoreleasepool {
        CWInterface *interface = [[CWWiFiClient sharedWiFiClient] interfaceWithName:[NSString stringWithUTF8String:name]];
        if (!interface || [interface security] != kCWSecurityNone) return 0;
        NSData *ssid = [interface ssidData];
        if (ssid.length < 1 || ssid.length > 32 || [interface security] != kCWSecurityNone) return 0;
        memcpy(out, ssid.bytes, ssid.length);
        return ssid.length;
    }
}
