//go:build darwin && cgo

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CoreWLAN/CoreWLAN.h>
#import <LocalAuthentication/LocalAuthentication.h>

static SecIdentityRef sohaEAPCopySystemIdentity(const unsigned char *der, unsigned long size, OSStatus *status) {
 SecKeychainRef keychain=NULL;
 *status=SecKeychainOpen("/Library/Keychains/System.keychain",&keychain);
 if(*status!=errSecSuccess)return NULL;
 CFArrayRef search=CFArrayCreate(NULL,(const void **)&keychain,1,&kCFTypeArrayCallBacks);
 LAContext *authentication=[[[LAContext alloc] init] autorelease];
 [authentication setInteractionNotAllowed:YES];
 const void *keys[]={kSecClass,kSecMatchSearchList,kSecMatchLimit,kSecReturnRef,kSecUseAuthenticationContext};
 const void *values[]={kSecClassIdentity,search,kSecMatchLimitAll,kCFBooleanTrue,(CFTypeRef)authentication};
 CFDictionaryRef query=CFDictionaryCreate(NULL,keys,values,5,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 CFTypeRef result=NULL;
 *status=SecItemCopyMatching(query,&result);
 CFRelease(query);CFRelease(search);CFRelease(keychain);
 if(*status!=errSecSuccess)return NULL;
 CFDataRef expected=CFDataCreate(NULL,der,size);
 SecIdentityRef found=NULL;
 if(CFGetTypeID(result)==CFArrayGetTypeID() && CFArrayGetCount(result)<=4096) {
  CFArrayRef identities=(CFArrayRef)result;
  for(CFIndex index=0;index<CFArrayGetCount(identities);index++) {
   SecIdentityRef identity=(SecIdentityRef)CFArrayGetValueAtIndex(identities,index);
   SecCertificateRef certificate=NULL;
   if(SecIdentityCopyCertificate(identity,&certificate)!=errSecSuccess)continue;
   CFDataRef actual=SecCertificateCopyData(certificate);CFRelease(certificate);
   int equal=actual && CFEqual(actual,expected);if(actual)CFRelease(actual);
   if(!equal)continue;
   SecKeyRef key=NULL;
   *status=SecIdentityCopyPrivateKey(identity,&key);
   if(*status==errSecSuccess && key) {
    CFDictionaryRef attributes=SecKeyCopyAttributes(key);
    CFTypeRef extractable=attributes?CFDictionaryGetValue(attributes,kSecAttrIsExtractable):NULL;
    int protectedKey=extractable && CFEqual(extractable,kCFBooleanFalse);
    if(attributes)CFRelease(attributes);CFRelease(key);
    if(protectedKey){found=(SecIdentityRef)CFRetain(identity);break;}
    *status=errSecAuthFailed;
   }
  }
 }
 CFRelease(expected);CFRelease(result);
 if(!found && *status==errSecSuccess)*status=errSecItemNotFound;
 return found;
}

int sohaEAPIdentityPresent(const unsigned char *der, unsigned long size) {
 @autoreleasepool {
  OSStatus status=errSecSuccess;
  SecIdentityRef identity=sohaEAPCopySystemIdentity(der,size,&status);
  if(identity)CFRelease(identity);
  return (int)status;
 }
}

int sohaEAPAssociate(const char *name, const char *ssid, const char *username, int security, const unsigned char *der, unsigned long size) {
 @autoreleasepool {
  OSStatus status=errSecSuccess;
  SecIdentityRef identity=sohaEAPCopySystemIdentity(der,size,&status);
  if(!identity)return (int)status;
  CWInterface *interface=[[CWWiFiClient sharedWiFiClient] interfaceWithName:[NSString stringWithUTF8String:name]];
  if(!interface){CFRelease(identity);return -1;}
  NSData *networkData=[NSData dataWithBytes:ssid length:strlen(ssid)];
  NSError *error=nil;
  NSSet<CWNetwork *> *networks=[interface scanForNetworksWithSSID:networkData error:&error];
  if(!networks){CFRelease(identity);return error?(int)[error code]:-2;}
  CWNetwork *selected=nil;
  for(CWNetwork *network in networks) {
   CWSecurity expected=security==3?kCWSecurityWPA3Enterprise:kCWSecurityWPA2Enterprise;
   if([[network ssidData] isEqualToData:networkData] && [network supportsSecurity:expected]) { selected=network;break; }
  }
  if(!selected){CFRelease(identity);return -3;}
  BOOL success=[interface associateToEnterpriseNetwork:selected identity:identity username:[NSString stringWithUTF8String:username] password:nil error:&error];
  CFRelease(identity);
  return success?0:(error?(int)[error code]:-4);
 }
}
