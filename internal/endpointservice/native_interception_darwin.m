//go:build darwin && cgo

#import <Foundation/Foundation.h>
#include <Security/Security.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <bsm/libbsm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/if_types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <libproc.h>
#include <sys/proc_info.h>

static char *niJSON(id value) {
    if (!value || ![NSJSONSerialization isValidJSONObject:@[value]]) return NULL;
    NSData *data = [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingFragmentsAllowed error:nil];
    if (!data || data.length > 1048576) return NULL;
    return strndup(data.bytes, data.length);
}
static id niDecode(const char *s) {
    if (!s || strlen(s)>1048576) return nil;
    return [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:s length:strlen(s)] options:NSJSONReadingFragmentsAllowed error:nil];
}
int ni_peer(int fd, unsigned int *words) {
    audit_token_t token = {0}; socklen_t size=sizeof(token);
    if(getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) || size!=sizeof(token))return -1;
    memcpy(words,&token,sizeof(token));return 0;
}
int ni_console(unsigned int uid, unsigned int asid) {
    CFStringRef key=SCDynamicStoreKeyCreateConsoleUser(NULL);
    CFTypeRef raw=key?SCDynamicStoreCopyValue(NULL,key):NULL;
    if(key)CFRelease(key);
    if(!raw)return -1;
    int count=0;
    if(CFGetTypeID(raw)==CFDictionaryGetTypeID()) {
        CFTypeRef sessions=CFDictionaryGetValue(raw,CFSTR("SessionInfo"));
        if(sessions && CFGetTypeID(sessions)==CFArrayGetTypeID() && CFArrayGetCount(sessions)<=64) {
            for(CFIndex i=0;i<CFArrayGetCount(sessions);i++) {
                CFTypeRef row=CFArrayGetValueAtIndex(sessions,i);
                if(CFGetTypeID(row)!=CFDictionaryGetTypeID())continue;
                CFTypeRef u=CFDictionaryGetValue(row,CFSTR("kCGSSessionUserIDKey"));
                CFTypeRef a=CFDictionaryGetValue(row,CFSTR("kCGSSessionAuditIDKey"));
                CFTypeRef c=CFDictionaryGetValue(row,CFSTR("kCGSSessionOnConsoleKey"));
                CFTypeRef d=CFDictionaryGetValue(row,CFSTR("kCGSessionLoginDoneKey"));
                long long uv=-1,av=-1;
                if(u&&a&&c&&d&&CFGetTypeID(u)==CFNumberGetTypeID()&&CFGetTypeID(a)==CFNumberGetTypeID()&&CFGetTypeID(c)==CFBooleanGetTypeID()&&CFGetTypeID(d)==CFBooleanGetTypeID()&&CFNumberGetValue(u,kCFNumberLongLongType,&uv)&&CFNumberGetValue(a,kCFNumberLongLongType,&av)&&uv==uid&&av==asid&&CFBooleanGetValue(c)&&CFBooleanGetValue(d))count++;
            }
        }
    }
    CFRelease(raw);return count==1?0:-1;
}
int ni_code(const unsigned int *words,const char *requirement,const char *path) {
    @autoreleasepool {
        audit_token_t token;memcpy(&token,words,sizeof(token));
        CFDataRef data=CFDataCreate(NULL,(const UInt8 *)&token,sizeof(token));
        const void *keys[]={kSecGuestAttributeAudit},*values[]={data};
        CFDictionaryRef attrs=CFDictionaryCreate(NULL,keys,values,1,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
        SecCodeRef code=NULL;SecRequirementRef req=NULL;
        CFStringRef text=CFStringCreateWithCString(NULL,requirement,kCFStringEncodingUTF8);
        OSStatus status=SecRequirementCreateWithString(text,kSecCSDefaultFlags,&req);
        if(status==0)status=SecCodeCopyGuestWithAttributes(NULL,attrs,kSecCSDefaultFlags,&code);
        if(status==0)status=SecCodeCheckValidity(code,kSecCSStrictValidate,req);
        CFURLRef url=NULL;
        if(status==0)status=SecCodeCopyPath(code,kSecCSDefaultFlags,&url);
        if(status==0) {
            NSString *actual=[(__bridge NSURL *)url path];
            if(![actual isEqualToString:[NSString stringWithUTF8String:path]])status=errSecCSNoSuchCode;
        }
        if(url)CFRelease(url);if(code)CFRelease(code);if(req)CFRelease(req);
        CFRelease(text);CFRelease(attrs);CFRelease(data);return status;
    }
}
static SCNetworkProtocolRef niProtocol(SCPreferencesRef prefs,NSString *service,NSString *entity) {
    SCNetworkServiceRef s=SCNetworkServiceCopy(prefs,(__bridge CFStringRef)service);
    if(!s)return NULL;
    SCNetworkProtocolRef p=SCNetworkServiceCopyProtocol(s,(__bridge CFStringRef)entity);CFRelease(s);return p;
}
// Missing values use JSON null, preserving absent automatic DNS configuration.
char *ni_setting(const char *service,const char *entity,const char *field) {
    @autoreleasepool {
        SCPreferencesRef prefs=SCPreferencesCreate(NULL,CFSTR("Soha interception read"),NULL);
        if(!prefs)return NULL;
        SCNetworkProtocolRef p=niProtocol(prefs,@(service),@(entity));
        char *result=NULL;
        if(p) {
            CFDictionaryRef cfg=SCNetworkProtocolGetConfiguration(p);
            id value=cfg?[(__bridge NSDictionary *)cfg objectForKey:@(field)]:nil;
            result=niJSON(value?:[NSNull null]);CFRelease(p);
        }
        CFRelease(prefs);return result;
    }
}
// 0 applied, 1 conflict, 2 definitely not applied, 3 commit/apply outcome unknown.
int ni_setting_cas(const char *service,const char *entity,const char *field,const char *before,const char *after) {
    @autoreleasepool {
        id expected=niDecode(before),desired=niDecode(after);
        if(!expected||!desired)return 2;
        SCPreferencesRef prefs=SCPreferencesCreate(NULL,CFSTR("Soha interception"),NULL);
        if(!prefs)return 2;
        int result=2;
        if(SCPreferencesLock(prefs,false)) {
            SCNetworkProtocolRef p=niProtocol(prefs,@(service),@(entity));
            if(p) {
                CFDictionaryRef cfg=SCNetworkProtocolGetConfiguration(p);
                NSMutableDictionary *next=cfg?[NSMutableDictionary dictionaryWithDictionary:(__bridge NSDictionary *)cfg]:[NSMutableDictionary dictionary];
                id current=next[@(field)]?:[NSNull null];
                if(![current isEqual:expected])result=1;
                else {
                    if(desired==[NSNull null])[next removeObjectForKey:@(field)];else next[@(field)]=desired;
                    if(SCNetworkProtocolSetConfiguration(p,(__bridge CFDictionaryRef)next)) {
                        result=3;
                        if(SCPreferencesCommitChanges(prefs)&&SCPreferencesApplyChanges(prefs))result=0;
                    }
                }
                CFRelease(p);
            }
            SCPreferencesUnlock(prefs);
        }
        CFRelease(prefs);return result;
    }
}
char *ni_network(void) {
    @autoreleasepool {
        SCDynamicStoreRef store=SCDynamicStoreCreate(NULL,CFSTR("Soha interception snapshot"),NULL,NULL);
        SCPreferencesRef prefs=SCPreferencesCreate(NULL,CFSTR("Soha interception snapshot"),NULL);
        if(!store||!prefs){if(store)CFRelease(store);if(prefs)CFRelease(prefs);return NULL;}
        NSMutableDictionary *result=[NSMutableDictionary dictionary];
        NSMutableArray *services=[NSMutableArray array],*resolvers=[NSMutableArray array];
        CFArrayRef all=SCNetworkServiceCopyAll(prefs);
        if(!all||CFArrayGetCount(all)>256){if(all)CFRelease(all);CFRelease(prefs);CFRelease(store);return NULL;}
        for(CFIndex i=0;i<CFArrayGetCount(all);i++) {
            SCNetworkServiceRef s=(SCNetworkServiceRef)CFArrayGetValueAtIndex(all,i);
            SCNetworkInterfaceRef iface=SCNetworkServiceGetInterface(s);
            NSString *sid=(__bridge NSString *)SCNetworkServiceGetServiceID(s);
            NSString *name=(__bridge NSString *)SCNetworkServiceGetName(s);
            NSString *bsd=iface?(__bridge NSString *)SCNetworkInterfaceGetBSDName(iface):nil;
            NSString *type=iface?(__bridge NSString *)SCNetworkInterfaceGetInterfaceType(iface):nil;
            [services addObject:@{@"id":sid?:@"",@"name":name?:@"",@"interface":bsd?:@"",@"type":type?:@""}];
        }
        CFRelease(all);
        for(NSString *family in @[@"IPv4",@"IPv6"]) {
            NSString *key=[@"State:/Network/Global/" stringByAppendingString:family];
            CFPropertyListRef v=SCDynamicStoreCopyValue(store,(__bridge CFStringRef)key);
            if(v&&CFGetTypeID(v)==CFDictionaryGetTypeID()) {
                id sid=[(__bridge NSDictionary *)v objectForKey:@"PrimaryService"];
                if(sid)result[family]=sid;
            }
            if(v)CFRelease(v);
        }
        CFArrayRef keys=SCDynamicStoreCopyKeyList(store,CFSTR("State:/Network/(Service/[^/]+|Global)/DNS"));
        if(keys&&CFArrayGetCount(keys)<=256)for(CFIndex i=0;i<CFArrayGetCount(keys);i++) {
            CFStringRef key=CFArrayGetValueAtIndex(keys,i);
            CFPropertyListRef v=SCDynamicStoreCopyValue(store,key);
            if(v&&CFGetTypeID(v)==CFDictionaryGetTypeID())[resolvers addObject:@{@"id":(__bridge NSString *)key,@"value":(__bridge NSDictionary *)v}];
            if(v)CFRelease(v);
        }
        if(keys)CFRelease(keys);
        result[@"services"]=services;result[@"resolvers"]=resolvers;
        CFRelease(prefs);CFRelease(store);return niJSON(result);
    }
}
char *ni_interfaces(void) {
    @autoreleasepool {
        struct ifaddrs *list=NULL;if(getifaddrs(&list))return NULL;
        NSMutableDictionary *rows=[NSMutableDictionary dictionary];
        int count=0;
        for(struct ifaddrs *p=list;p;p=p->ifa_next) {
            if(++count>4096){freeifaddrs(list);return NULL;}
            if(!p->ifa_addr)continue;
            NSString *name=@(p->ifa_name);
            NSMutableDictionary *row=rows[name];
            if(!row){row=[@{@"name":name,@"index":@(if_nametoindex(p->ifa_name)),@"addresses":[NSMutableArray array],@"kind":@"unknown",@"stamp":@""} mutableCopy];rows[name]=row;}
            int family=p->ifa_addr->sa_family;
            if(family==AF_LINK&&p->ifa_data) {
                struct if_data *d=p->ifa_data;
                row[@"stamp"]=[NSString stringWithFormat:@"%lld:%d",(long long)d->ifi_lastchange.tv_sec,d->ifi_lastchange.tv_usec];
                if(p->ifa_flags&IFF_LOOPBACK)row[@"kind"]=@"loopback";
                else if(p->ifa_flags&IFF_POINTOPOINT)row[@"kind"]=@"tunnel";
                else if(d->ifi_type==IFT_ETHER && !(p->ifa_flags&IFF_POINTOPOINT))row[@"kind"]=@"physical";
            }
            if((family==AF_INET||family==AF_INET6)&&p->ifa_netmask) {
                char text[INET6_ADDRSTRLEN];void *addr;unsigned char *mask;int size;
                if(family==AF_INET){addr=&((struct sockaddr_in *)p->ifa_addr)->sin_addr;mask=(unsigned char *)&((struct sockaddr_in *)p->ifa_netmask)->sin_addr;size=4;}
                else {addr=&((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr;mask=(unsigned char *)&((struct sockaddr_in6 *)p->ifa_netmask)->sin6_addr;size=16;}
                int bits=0;bool zero=false,valid=true;
                for(int j=0;j<size;j++)for(int k=7;k>=0;k--){if(mask[j]&(1<<k)){if(zero)valid=false;bits++;}else zero=true;}
                if(valid&&inet_ntop(family,addr,text,sizeof(text))) [row[@"addresses"] addObject:[NSString stringWithFormat:@"%s/%d",text,bits]];
            }
        }
        freeifaddrs(list);return niJSON([rows allValues]);
    }
}
unsigned int ni_route_metric(const void *data,int size) {
    if(size<(int)sizeof(struct rt_msghdr))return UINT_MAX;
    return ((const struct rt_msghdr *)data)->rtm_rmx.rmx_hopcount;
}
int ni_route_setmetric(void *data,int size,unsigned int metric) {
    if(size<(int)sizeof(struct rt_msghdr))return -1;
    struct rt_msghdr *h=data;h->rtm_inits=RTV_HOPCOUNT;h->rtm_rmx.rmx_hopcount=metric;return 0;
}

// Public libproc metadata: no socket is opened, rebound, or probed on the network.
int ni_listener(unsigned int pid,int tcp,int family,unsigned short port,const void *address) {
    if(pid==0||pid>INT_MAX||!address||port==0)return -1;
    int size=proc_pidinfo((int)pid,PROC_PIDLISTFDS,0,NULL,0);
    if(size<=0||size>(int)(4096*sizeof(struct proc_fdinfo)))return -1;
    int capacity=size+(int)(32*sizeof(struct proc_fdinfo));
    struct proc_fdinfo *fds=calloc(1,capacity);
    if(!fds)return -1;
    int used=proc_pidinfo((int)pid,PROC_PIDLISTFDS,0,fds,capacity);
    if(used<=0||used>=capacity||used%(int)sizeof(*fds)){free(fds);return -1;}
    int matches=0,matchedFD=-1;struct socket_fdinfo selected={0};
    for(int i=0;i<used/(int)sizeof(*fds);i++) {
        if(fds[i].proc_fdtype!=PROX_FDTYPE_SOCKET)continue;
        struct socket_fdinfo info={0};
        if(proc_pidfdinfo((int)pid,fds[i].proc_fd,PROC_PIDFDSOCKETINFO,&info,sizeof(info))!=sizeof(info)){free(fds);return -1;}
        struct socket_info *so=&info.psi;
        if(so->soi_family!=family||so->soi_protocol!=(tcp?IPPROTO_TCP:IPPROTO_UDP))continue;
        if((tcp&&so->soi_kind!=SOCKINFO_TCP)||(!tcp&&so->soi_kind!=SOCKINFO_IN))continue;
        struct in_sockinfo *in=tcp?&so->soi_proto.pri_tcp.tcpsi_ini:&so->soi_proto.pri_in;
        if(ntohs((unsigned short)in->insi_lport)!=port)continue;
        if(in->insi_fport!=0)continue;
        const void *local=family==AF_INET?(const void *)&in->insi_laddr.ina_46.i46a_addr4:(const void *)&in->insi_laddr.ina_6;
        int length=family==AF_INET?4:16;
        unsigned char zero[16]={0};
        if(!memcmp(local,zero,length)){free(fds);return -1;}
        if(memcmp(local,address,length))continue;
        if((family==AF_INET&&in->insi_vflag!=INI_IPV4)||(family==AF_INET6&&in->insi_vflag!=INI_IPV6)){free(fds);return -1;}
        if((tcp&&so->soi_proto.pri_tcp.tcpsi_state!=TSI_S_LISTEN)||(so->soi_options&SO_REUSEPORT)){free(fds);return -1;}
        matches++;matchedFD=fds[i].proc_fd;selected=info;
    }
    free(fds);
    if(matches!=1)return -1;
    struct socket_fdinfo current={0};
    if(proc_pidfdinfo((int)pid,matchedFD,PROC_PIDFDSOCKETINFO,&current,sizeof(current))!=sizeof(current))return -1;
    if(current.psi.soi_so!=selected.psi.soi_so||current.psi.soi_pcb!=selected.psi.soi_pcb||current.psi.soi_kind!=selected.psi.soi_kind||current.psi.soi_options!=selected.psi.soi_options)return -1;
    struct in_sockinfo *a=tcp?&selected.psi.soi_proto.pri_tcp.tcpsi_ini:&selected.psi.soi_proto.pri_in;
    struct in_sockinfo *b=tcp?&current.psi.soi_proto.pri_tcp.tcpsi_ini:&current.psi.soi_proto.pri_in;
    if(a->insi_gencnt!=b->insi_gencnt||a->insi_lport!=b->insi_lport||a->insi_fport!=b->insi_fport||memcmp(&a->insi_laddr,&b->insi_laddr,sizeof(a->insi_laddr)))return -1;
    if(tcp&&current.psi.soi_proto.pri_tcp.tcpsi_state!=TSI_S_LISTEN)return -1;
    return 0;
}
