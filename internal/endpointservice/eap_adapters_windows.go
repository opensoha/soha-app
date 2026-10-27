//go:build windows

package endpointservice

import (
	"context"
	"errors"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func windowsEAPAdapters(ctx context.Context) ([]EAPAdapter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	size := uint32(15 << 10)
	for attempt := 0; attempt < 3; attempt++ {
		if size > 1<<20 {
			return nil, errors.New("Windows EAP adapter inventory exceeds the safe size")
		}
		raw := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&raw[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, err
		}
		adapters := []EAPAdapter{}
		seen := map[string]bool{}
		for item, count := first, 0; item != nil; item, count = item.Next, count+1 {
			if count >= 128 {
				return nil, errors.New("Windows EAP adapter inventory exceeds 128 interfaces")
			}
			medium := ""
			switch item.IfType {
			case 6:
				medium = "wired"
			case 71:
				medium = "wifi"
			default:
				continue
			}
			guid, err := windows.GUIDFromString(windows.BytePtrToString(item.AdapterName))
			name := windows.UTF16PtrToString(item.FriendlyName)
			if err != nil || name == "" || len(name) > 256 || strings.ContainsAny(name, "\x00\r\n/\\:*?\"<>|") || item.PhysicalAddressLength != 6 {
				continue
			}
			id := strings.ToLower(guid.String())
			if seen[id] {
				return nil, errors.New("Windows EAP adapter inventory has a duplicate interface GUID")
			}
			seen[id] = true
			adapters = append(adapters, EAPAdapter{ID: id, Name: name, Medium: medium, MACAddress: net.HardwareAddr(item.PhysicalAddress[:6]).String(), Enabled: item.OperStatus != windows.IfOperStatusNotPresent && item.OperStatus != windows.IfOperStatusLowerLayerDown, LinkUp: item.OperStatus == windows.IfOperStatusUp})
		}
		return adapters, nil
	}
	return nil, errors.New("Windows EAP adapter inventory changed repeatedly")
}

func validateWindowsEAPAdapter(ctx context.Context, selected EAPAdapter, requireEnabled bool) error {
	adapters, err := windowsEAPAdapters(ctx)
	if err != nil {
		return err
	}
	return matchWindowsEAPAdapter(adapters, selected, requireEnabled)
}

func matchWindowsEAPAdapter(adapters []EAPAdapter, selected EAPAdapter, requireEnabled bool) error {
	for _, adapter := range adapters {
		if adapter.ID == selected.ID && adapter.Name == selected.Name && adapter.Medium == selected.Medium && strings.EqualFold(adapter.MACAddress, selected.MACAddress) && (!requireEnabled || adapter.Enabled) {
			return nil
		}
	}
	return errors.New("selected Windows EAP adapter changed or is unavailable")
}
