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
static int sohaDNSMetadataMatches(sohaDNS *h,CFDictionaryRef current) {
 if(!h||!current||CFGetTypeID(current)!=CFDictionaryGetTypeID())return 0;
 CFMutableDictionaryRef a=CFDictionaryCreateMutableCopy(NULL,0,current),b=CFDictionaryCreateMutableCopy(NULL,0,h->dns);
 CFDictionaryRemoveValue(a,kSCPropNetDNSServerAddresses);CFDictionaryRemoveValue(b,kSCPropNetDNSServerAddresses);
 int same=CFEqual(a,b);CFRelease(a);CFRelease(b);
 for(int i=0;i<2;i++)if(h->ipKeys[i]&&!sohaDNSValueMatches(h,h->ipKeys[i],h->ip[i],0))same=0;
 return same;
}
static char *sohaDNSReadServers(sohaDNS *h) {
 if(!h)return NULL;
 CFPropertyListRef raw=SCDynamicStoreCopyValue(h->store,h->dnsKey);
 if(!raw)return NULL;
 if(!sohaDNSMetadataMatches(h,raw)){CFRelease(raw);return NULL;}
 CFTypeRef values=CFDictionaryGetValue(raw,kSCPropNetDNSServerAddresses);
 if(!values||CFGetTypeID(values)!=CFArrayGetTypeID()||CFArrayGetCount(values)>64){CFRelease(raw);return NULL;}
 char *result=calloc(1,8193);size_t size=0;
 if(!result){CFRelease(raw);return NULL;}
 for(CFIndex i=0;i<CFArrayGetCount(values);i++) {
  CFTypeRef value=CFArrayGetValueAtIndex(values,i);char text[128];
  if(CFGetTypeID(value)!=CFStringGetTypeID()||!CFStringGetCString(value,text,sizeof(text),kCFStringEncodingUTF8)||strchr(text,'\n')){free(result);CFRelease(raw);return NULL;}
  size_t n=strlen(text);if(size+n+1>8192){free(result);CFRelease(raw);return NULL;}
  memcpy(result+size,text,n);size+=n;result[size++]='\n';
 }
 CFRelease(raw);return result;
}
// One owned dictionary update; no key is created if the old handle disappeared.
static int sohaDNSCAS(sohaDNS *h,const char *before,const char *after) {
 if(!h||!sohaDNSCheck(h,0))return 1;
 CFArrayRef old=sohaStrings(before),next=sohaStrings(after);
 CFTypeRef expected=CFDictionaryGetValue(h->dns,kSCPropNetDNSServerAddresses);
 if(!expected||!CFEqual(expected,old)){CFRelease(old);CFRelease(next);return 1;}
 CFMutableDictionaryRef value=CFDictionaryCreateMutableCopy(NULL,0,h->dns);
 CFDictionarySetValue(value,kSCPropNetDNSServerAddresses,next);
 CFRelease(old);CFRelease(next);
 int result=3;
 if(SCDynamicStoreSetValue(h->store,h->dnsKey,value)) {
  CFRelease(h->dns);h->dns=value;
  if(sohaDNSCheck(h,0))result=0;
 }else CFRelease(value);
 return result;
}
static int sohaDNSHandleAbsent(const char *service) {
 SCDynamicStoreRef store=SCDynamicStoreCreate(NULL,CFSTR("Soha owned DNS recovery"),NULL,NULL);
 if(!store)return -1;
 CFStringRef sid=sohaString(service);CFStringRef entities[]={kSCEntNetDNS,kSCEntNetIPv4,kSCEntNetIPv6};int absent=1;
 for(int i=0;i<3;i++) {
  CFStringRef key=SCDynamicStoreKeyCreateNetworkServiceEntity(NULL,kSCDynamicStoreDomainState,sid,entities[i]);
  CFPropertyListRef value=SCDynamicStoreCopyValue(store,key);CFRelease(key);
  if(value){absent=0;CFRelease(value);}else if(SCError()!=kSCStatusNoKey){absent=-1;break;}
 }
 CFRelease(sid);CFRelease(store);return absent;
}

*/
import "C"

import (
	"errors"
	"net/netip"
	"strings"
	"unsafe"
)

type darwinDNS struct {
	handle    *C.sohaDNS
	serviceID string
	calls     *darwinDNSCalls
}

func openDarwinDNS(iface string, addresses, servers []string) (*darwinDNS, error) {
	ipv4, ipv6, err := splitDarwinDNSAddresses(addresses)
	if err != nil {
		return nil, err
	}
	serviceID := "com.opensoha.vpn." + randomID()
	service := C.CString(serviceID)
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
	return &darwinDNS{handle: h, serviceID: serviceID}, nil
}
func (d *darwinDNS) matches() bool {
	if d != nil && d.calls != nil && d.calls.matches != nil {
		return d.calls.matches()
	}
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

func (d *darwinDNS) currentServers() ([]string, error) {
	if d == nil {
		return nil, errors.New("owned macOS DNS handle is absent")
	}
	if d.calls != nil && d.calls.read != nil {
		return d.calls.read()
	}
	raw := C.sohaDNSReadServers(d.handle)
	if raw == nil {
		return nil, errors.New("owned macOS DNS state could not be read")
	}
	defer C.free(unsafe.Pointer(raw))
	text := strings.TrimSuffix(C.GoString(raw), "\n")
	var servers []string
	if text != "" {
		servers = strings.Split(text, "\n")
	}
	for _, server := range servers {
		if _, err := netip.ParseAddr(server); err != nil {
			return nil, errors.New("owned macOS DNS state is invalid")
		}
	}
	return servers, nil
}
func (d *darwinDNS) compareServers(before, after []string) (string, error) {
	if d == nil {
		return "not_applied", errors.New("owned macOS DNS handle is absent")
	}
	if d.calls != nil && d.calls.cas != nil {
		return d.calls.cas(before, after)
	}
	b, a := C.CString(strings.Join(before, "\n")), C.CString(strings.Join(after, "\n"))
	defer C.free(unsafe.Pointer(b))
	defer C.free(unsafe.Pointer(a))
	status := int(C.sohaDNSCAS(d.handle, b, a))
	if status == 0 {
		return "applied", nil
	}
	if status == 1 {
		return "conflict", errors.New("owned macOS DNS changed externally")
	}
	return "unknown", errors.New("owned macOS DNS write could not be confirmed")
}
func darwinWGHandleAbsent(service string) (bool, error) {
	value := C.CString(service)
	defer C.free(unsafe.Pointer(value))
	status := C.sohaDNSHandleAbsent(value)
	if status < 0 {
		return false, errors.New("old macOS DNS handle could not be inspected")
	}
	return status == 1, nil
}
