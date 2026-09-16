//go:build darwin && cgo

package endpointservice

/*
#cgo LDFLAGS: -framework SystemConfiguration -framework CoreFoundation
#include <SystemConfiguration/SystemConfiguration.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
 SCDynamicStoreRef store;
 CFStringRef dnsKey, ipKey;
 CFDictionaryRef dns, ip;
} sohaDNS;

static CFStringRef sohaString(const char *text) { return CFStringCreateWithCString(NULL,text,kCFStringEncodingUTF8); }
static CFArrayRef sohaStrings(const char *lines) {
 CFMutableArrayRef array=CFArrayCreateMutable(NULL,0,&kCFTypeArrayCallBacks);
 char *copy=strdup(lines), *save=NULL, *part=strtok_r(copy,"\n",&save);
 while(part) { CFStringRef value=sohaString(part); CFArrayAppendValue(array,value); CFRelease(value); part=strtok_r(NULL,"\n",&save); }
 free(copy); return array;
}
static int sohaDNSMatches(sohaDNS *h) {
 CFPropertyListRef dns=SCDynamicStoreCopyValue(h->store,h->dnsKey);
 CFPropertyListRef ip=SCDynamicStoreCopyValue(h->store,h->ipKey);
 int ok=dns && ip && CFEqual(dns,h->dns) && CFEqual(ip,h->ip);
 if(dns)CFRelease(dns);if(ip)CFRelease(ip);return ok;
}
static void sohaDNSFree(sohaDNS *h) {
 if(h->dns)CFRelease(h->dns);if(h->ip)CFRelease(h->ip);
 if(h->dnsKey)CFRelease(h->dnsKey);if(h->ipKey)CFRelease(h->ipKey);
 if(h->store)CFRelease(h->store);free(h);
}
static sohaDNS *sohaDNSOpen(const char *service,const char *iface,const char *addresses,const char *servers) {
 sohaDNS *h=calloc(1,sizeof(*h));
 const void *optionKeys[]={kSCDynamicStoreUseSessionKeys}, *optionValues[]={kCFBooleanTrue};
 CFDictionaryRef options=CFDictionaryCreate(NULL,optionKeys,optionValues,1,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 h->store=SCDynamicStoreCreateWithOptions(NULL,CFSTR("OpenSoha VPN"),options,NULL,NULL);CFRelease(options);
 if(!h->store){sohaDNSFree(h);return NULL;}
 CFStringRef serviceID=sohaString(service), interfaceName=sohaString(iface);
 h->dnsKey=SCDynamicStoreKeyCreateNetworkServiceEntity(NULL,kSCDynamicStoreDomainState,serviceID,kSCEntNetDNS);
 h->ipKey=SCDynamicStoreKeyCreateNetworkServiceEntity(NULL,kSCDynamicStoreDomainState,serviceID,kSCEntNetIPv4);
 CFArrayRef serverArray=sohaStrings(servers), addressArray=sohaStrings(addresses);
 const void *emptyDomain[]={CFSTR("")};
 CFArrayRef domains=CFArrayCreate(NULL,emptyDomain,1,&kCFTypeArrayCallBacks);
 const void *dnsKeys[]={kSCPropNetDNSServerAddresses,kSCPropNetDNSSupplementalMatchDomains,kSCPropInterfaceName};
 const void *dnsValues[]={serverArray,domains,interfaceName};
 h->dns=CFDictionaryCreate(NULL,dnsKeys,dnsValues,3,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 const void *ipKeys[]={kSCPropInterfaceName,kSCPropNetIPv4Addresses};
 const void *ipValues[]={interfaceName,addressArray};
 h->ip=CFDictionaryCreate(NULL,ipKeys,ipValues,2,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 CFRelease(serverArray);CFRelease(addressArray);CFRelease(domains);CFRelease(interfaceName);CFRelease(serviceID);
 if(!SCDynamicStoreAddTemporaryValue(h->store,h->ipKey,h->ip) || !SCDynamicStoreAddTemporaryValue(h->store,h->dnsKey,h->dns)) {sohaDNSFree(h);return NULL;}
 return h;
}
static int sohaDNSClose(sohaDNS *h) {
 CFPropertyListRef current=SCDynamicStoreCopyValue(h->store,h->dnsKey);
 if(current && !CFEqual(current,h->dns)){CFRelease(current);return 0;}
 if(current){CFRelease(current);if(!SCDynamicStoreRemoveValue(h->store,h->dnsKey))return 0;}
 current=SCDynamicStoreCopyValue(h->store,h->ipKey);
 if(current && !CFEqual(current,h->ip)){CFRelease(current);return 0;}
 if(current){CFRelease(current);if(!SCDynamicStoreRemoveValue(h->store,h->ipKey))return 0;}
 sohaDNSFree(h);return 1;
}
*/
import "C"

import (
	"errors"
	"strings"
	"unsafe"
)

type darwinDNS struct{ handle *C.sohaDNS }

func openDarwinDNS(iface string, addresses, servers []string) (*darwinDNS, error) {
	service := C.CString("com.opensoha.vpn." + randomID())
	defer C.free(unsafe.Pointer(service))
	name := C.CString(iface)
	defer C.free(unsafe.Pointer(name))
	address := C.CString(strings.Join(addresses, "\n"))
	defer C.free(unsafe.Pointer(address))
	dns := C.CString(strings.Join(servers, "\n"))
	defer C.free(unsafe.Pointer(dns))
	h := C.sohaDNSOpen(service, name, address, dns)
	if h == nil {
		return nil, errors.New("could not install temporary macOS VPN DNS settings")
	}
	return &darwinDNS{handle: h}, nil
}
func (d *darwinDNS) matches() bool {
	return d != nil && d.handle != nil && C.sohaDNSMatches(d.handle) != 0
}
func (d *darwinDNS) close() error {
	if d == nil || d.handle == nil {
		return nil
	}
	if C.sohaDNSClose(d.handle) == 0 {
		return errors.New("VPN DNS settings changed externally; cleanup must be completed before reconnecting")
	}
	d.handle = nil
	return nil
}
