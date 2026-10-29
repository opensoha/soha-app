//go:build darwin && cgo

package endpointservice

/*
#cgo LDFLAGS: -framework SystemConfiguration -framework CoreFoundation
#include <SystemConfiguration/SystemConfiguration.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
 SCDynamicStoreRef store;
 CFStringRef dnsKey, ipKeys[2];
 CFDictionaryRef dns, ip[2];
} sohaDNS;

static CFStringRef sohaString(const char *text) { return CFStringCreateWithCString(NULL,text,kCFStringEncodingUTF8); }
static CFArrayRef sohaStrings(const char *lines) {
 CFMutableArrayRef array=CFArrayCreateMutable(NULL,0,&kCFTypeArrayCallBacks);
 char *copy=strdup(lines), *save=NULL, *part=strtok_r(copy,"\n",&save);
 while(part) { CFStringRef value=sohaString(part); CFArrayAppendValue(array,value); CFRelease(value); part=strtok_r(NULL,"\n",&save); }
 free(copy); return array;
}
static int sohaDNSValueMatches(sohaDNS *h,CFStringRef key,CFDictionaryRef expected,int allowMissing) {
 CFPropertyListRef current=SCDynamicStoreCopyValue(h->store,key);
 int ok=current ? CFEqual(current,expected) : allowMissing;
 if(current)CFRelease(current);return ok;
}
static int sohaDNSCheck(sohaDNS *h,int allowMissing) {
 if(!sohaDNSValueMatches(h,h->dnsKey,h->dns,allowMissing))return 0;
 for(int i=0;i<2;i++)if(h->ipKeys[i] && !sohaDNSValueMatches(h,h->ipKeys[i],h->ip[i],allowMissing))return 0;
 return 1;
}
static int sohaDNSMatches(sohaDNS *h) {
 return sohaDNSCheck(h,0);
}
static void sohaDNSFree(sohaDNS *h) {
 if(h->dns)CFRelease(h->dns);
 if(h->dnsKey)CFRelease(h->dnsKey);
 for(int i=0;i<2;i++) {
  if(h->ip[i])CFRelease(h->ip[i]);
  if(h->ipKeys[i])CFRelease(h->ipKeys[i]);
 }
 if(h->store)CFRelease(h->store);free(h);
}
static sohaDNS *sohaDNSOpen(const char *service,const char *iface,const char *ipv4,const char *ipv6,const char *servers) {
 sohaDNS *h=calloc(1,sizeof(*h));
 const void *optionKeys[]={kSCDynamicStoreUseSessionKeys}, *optionValues[]={kCFBooleanTrue};
 CFDictionaryRef options=CFDictionaryCreate(NULL,optionKeys,optionValues,1,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 h->store=SCDynamicStoreCreateWithOptions(NULL,CFSTR("OpenSoha VPN"),options,NULL,NULL);CFRelease(options);
 if(!h->store){sohaDNSFree(h);return NULL;}
 CFStringRef serviceID=sohaString(service), interfaceName=sohaString(iface);
 h->dnsKey=SCDynamicStoreKeyCreateNetworkServiceEntity(NULL,kSCDynamicStoreDomainState,serviceID,kSCEntNetDNS);
 CFArrayRef serverArray=sohaStrings(servers);
 const void *emptyDomain[]={CFSTR("")};
 CFArrayRef domains=CFArrayCreate(NULL,emptyDomain,1,&kCFTypeArrayCallBacks);
 const void *dnsKeys[]={kSCPropNetDNSServerAddresses,kSCPropNetDNSSupplementalMatchDomains,kSCPropInterfaceName};
 const void *dnsValues[]={serverArray,domains,interfaceName};
 h->dns=CFDictionaryCreate(NULL,dnsKeys,dnsValues,3,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 const char *addresses[]={ipv4,ipv6};
 CFStringRef entities[]={kSCEntNetIPv4,kSCEntNetIPv6};
 CFStringRef addressKeys[]={kSCPropNetIPv4Addresses,kSCPropNetIPv6Addresses};
 for(int i=0;i<2;i++)if(addresses[i][0]) {
  h->ipKeys[i]=SCDynamicStoreKeyCreateNetworkServiceEntity(NULL,kSCDynamicStoreDomainState,serviceID,entities[i]);
  CFArrayRef values=sohaStrings(addresses[i]);
  const void *keys[]={kSCPropInterfaceName,addressKeys[i]}, *ipValues[]={interfaceName,values};
  h->ip[i]=CFDictionaryCreate(NULL,keys,ipValues,2,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
  CFRelease(values);
 }
 CFRelease(serverArray);CFRelease(domains);CFRelease(interfaceName);CFRelease(serviceID);
 for(int i=0;i<2;i++)if(h->ipKeys[i] && !SCDynamicStoreAddTemporaryValue(h->store,h->ipKeys[i],h->ip[i])) {sohaDNSFree(h);return NULL;}
 if(!SCDynamicStoreAddTemporaryValue(h->store,h->dnsKey,h->dns)) {sohaDNSFree(h);return NULL;}
 return h;
}
static int sohaDNSRemove(sohaDNS *h,CFStringRef key,CFDictionaryRef expected) {
 CFPropertyListRef current=SCDynamicStoreCopyValue(h->store,key);
 if(!current)return 1;
 int owned=CFEqual(current,expected);CFRelease(current);
 return owned && SCDynamicStoreRemoveValue(h->store,key);
}
static int sohaDNSClose(sohaDNS *h) {
 if(!sohaDNSCheck(h,1))return 0;
 if(!sohaDNSRemove(h,h->dnsKey,h->dns))return 0;
 for(int i=0;i<2;i++)if(h->ipKeys[i] && !sohaDNSRemove(h,h->ipKeys[i],h->ip[i]))return 0;
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
	ipv4, ipv6, err := splitDarwinDNSAddresses(addresses)
	if err != nil {
		return nil, err
	}
	service := C.CString("com.opensoha.vpn." + randomID())
	defer C.free(unsafe.Pointer(service))
	name := C.CString(iface)
	defer C.free(unsafe.Pointer(name))
	address4 := C.CString(strings.Join(ipv4, "\n"))
	defer C.free(unsafe.Pointer(address4))
	address6 := C.CString(strings.Join(ipv6, "\n"))
	defer C.free(unsafe.Pointer(address6))
	dns := C.CString(strings.Join(servers, "\n"))
	defer C.free(unsafe.Pointer(dns))
	h := C.sohaDNSOpen(service, name, address4, address6, dns)
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
