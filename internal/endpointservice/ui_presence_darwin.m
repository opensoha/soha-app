//go:build darwin && cgo

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <string.h>

int soha_verify_ui_code(int pid, const char *path, const char *requirement) {
    CFStringRef text = CFStringCreateWithCString(NULL, requirement, kCFStringEncodingUTF8);
    SecRequirementRef expected = NULL;
    OSStatus status = text ? SecRequirementCreateWithString(text, kSecCSDefaultFlags, &expected) : errSecParam;
    if (text) CFRelease(text);
    if (status != errSecSuccess) return (int)status;
    if (pid > 0) {
        CFNumberRef number = CFNumberCreate(NULL, kCFNumberIntType, &pid);
        const void *keys[] = { kSecGuestAttributePid };
        const void *values[] = { number };
        CFDictionaryRef attributes = number ? CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks) : NULL;
        SecCodeRef code = NULL;
        status = attributes ? SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code) : errSecParam;
        if (status == errSecSuccess) status = SecCodeCheckValidity(code, kSecCSStrictValidate, expected);
        if (code) CFRelease(code);
        if (attributes) CFRelease(attributes);
        if (number) CFRelease(number);
    } else {
        CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
        SecStaticCodeRef code = NULL;
        status = url ? SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) : errSecParam;
        if (status == errSecSuccess) status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate, expected);
        if (code) CFRelease(code);
        if (url) CFRelease(url);
    }
    CFRelease(expected);
    return (int)status;
}
