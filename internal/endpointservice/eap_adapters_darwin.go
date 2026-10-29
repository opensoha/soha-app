//go:build darwin && cgo

package endpointservice

/*
#cgo LDFLAGS: -framework SystemConfiguration -framework CoreFoundation
#include <SystemConfiguration/SystemConfiguration.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
 char id[128], name[128], mac[128];
 int wired, position, enabled;
} sohaEAPAdapter;
typedef struct { int count; sohaEAPAdapter adapters[128]; } sohaEAPAdapters;

static sohaEAPAdapters *sohaEAPCopyAdapters(void) {
 SCPreferencesRef preferences=SCPreferencesCreate(NULL,CFSTR("Soha EAP adapter inventory"),NULL);
 if(!preferences)return NULL;
 SCNetworkSetRef set=SCNetworkSetCopyCurrent(preferences);
 if(!set){CFRelease(preferences);return NULL;}
 CFArrayRef order=SCNetworkSetGetServiceOrder(set);
 if(!order){CFRelease(set);CFRelease(preferences);return NULL;}
 sohaEAPAdapters *result=calloc(1,sizeof(*result));
 if(!result){CFRelease(set);CFRelease(preferences);return NULL;}
 int position=0;
 for(CFIndex index=0;index<CFArrayGetCount(order);index++) {
  CFStringRef id=CFArrayGetValueAtIndex(order,index);
  SCNetworkServiceRef service=SCNetworkServiceCopy(preferences,id);
  if(!service)continue;
  SCNetworkInterfaceRef interface=SCNetworkServiceGetInterface(service);
  CFStringRef type=interface?SCNetworkInterfaceGetInterfaceType(interface):NULL;
  int wired=type && CFEqual(type,kSCNetworkInterfaceTypeEthernet);
  int wifi=type && CFEqual(type,kSCNetworkInterfaceTypeIEEE80211);
  CFStringRef name=interface?SCNetworkInterfaceGetBSDName(interface):NULL;
  if((!wired && !wifi) || !name){CFRelease(service);continue;}
  sohaEAPAdapter adapter={0};
  int valid=CFStringGetCString(id,adapter.id,sizeof(adapter.id),kCFStringEncodingUTF8) && CFStringGetCString(name,adapter.name,sizeof(adapter.name),kCFStringEncodingUTF8);
  CFStringRef mac=SCNetworkInterfaceGetHardwareAddressString(interface);
  if(mac)valid=valid && CFStringGetCString(mac,adapter.mac,sizeof(adapter.mac),kCFStringEncodingUTF8);
  int duplicate=0;
  for(int n=0;n<result->count;n++)if(!strcmp(result->adapters[n].name,adapter.name))duplicate=1;
  if(!valid){result->count=-1;CFRelease(service);break;}
  if(duplicate){CFRelease(service);continue;}
  if(result->count==128){result->count=-1;CFRelease(service);break;}
  adapter.wired=wired;
  adapter.position=wired?++position:0;
  adapter.enabled=SCNetworkServiceGetEnabled(service);
  result->adapters[result->count++]=adapter;
  CFRelease(service);
 }
 CFRelease(set);CFRelease(preferences);return result;
}
*/
import "C"

import (
	"context"
	"errors"
	"net"
	"strings"
	"unsafe"
)

func darwinEAPAdapters(ctx context.Context) ([]EAPAdapter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	values := C.sohaEAPCopyAdapters()
	if values == nil {
		return nil, errors.New("macOS network service order is unavailable")
	}
	defer C.free(unsafe.Pointer(values))
	if values.count < 0 {
		return nil, errors.New("macOS EAP adapter inventory exceeded its safe limit")
	}
	result := make([]EAPAdapter, 0, int(values.count))
	for index := 0; index < int(values.count); index++ {
		value := &values.adapters[index]
		adapter := EAPAdapter{ID: C.GoString(&value.id[0]), Name: C.GoString(&value.name[0]), MACAddress: strings.ToLower(C.GoString(&value.mac[0])), Medium: "wifi", Enabled: value.enabled != 0, EthernetPosition: int(value.position)}
		if value.wired != 0 {
			adapter.Medium = "wired"
		}
		current, err := net.InterfaceByName(adapter.Name)
		if err != nil {
			continue
		}
		adapter.MACAddress = strings.ToLower(current.HardwareAddr.String())
		adapter.LinkUp = current.Flags&net.FlagUp != 0
		result = append(result, adapter)
	}
	return result, ctx.Err()
}
