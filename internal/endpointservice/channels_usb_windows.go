//go:build windows

package endpointservice

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"

	ec "github.com/opensoha/soha-contracts/endpointcontrol"
	"golang.org/x/sys/windows"
)

const ioctlStorageQueryProperty = 0x002d1400
const fsctlLockVolume = 0x00090018

func enumerateChannelVolumes() ([]string, error) {
	var buffer [1024]uint16
	handle, err := windows.FindFirstVolume(&buffer[0], uint32(len(buffer)))
	if err != nil {
		return nil, err
	}
	defer windows.FindVolumeClose(handle)
	names := []string{}
	for {
		name := windows.UTF16ToString(buffer[:])
		if !strings.HasPrefix(name, `\\?\Volume{`) || !strings.HasSuffix(name, `}\`) {
			return nil, errors.New("unsupported volume identity")
		}
		names = append(names, name)
		if len(names) > 256 {
			return nil, errors.New("too many mounted volumes")
		}
		err = windows.FindNextVolume(handle, &buffer[0], uint32(len(buffer)))
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
	}
}
func openChannelVolume(name string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(strings.TrimSuffix(name, `\`))
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
}
func volumeIsUSB(h windows.Handle) (bool, error) {
	// STORAGE_DEVICE_DESCRIPTOR has BusType at offset 28; bound variable data.
	var query [12]byte
	var descriptor [4096]byte
	var returned uint32
	err := windows.DeviceIoControl(h, ioctlStorageQueryProperty, &query[0], uint32(len(query)), &descriptor[0], uint32(len(descriptor)), &returned, nil)
	if err != nil {
		return false, err
	}
	if returned < 36 || binary.LittleEndian.Uint32(descriptor[4:8]) < 36 {
		return false, errors.New("invalid storage descriptor")
	}
	return binary.LittleEndian.Uint32(descriptor[28:32]) == 7, nil
}
func (s *windowsChannels) reconcileUSB(ctx context.Context, enabled bool) ec.Channel {
	result := channelResult("usb", "current_usb_volumes", enabled)
	if !enabled {
		for name, h := range s.volumes {
			if windows.CloseHandle(h) != nil {
				result.State = "failed"
				result.ReasonCode = "volume_close_failed"
			} else {
				delete(s.volumes, name)
			}
		}
		return result
	}
	names, err := enumerateChannelVolumes()
	if err != nil {
		result.State = "failed"
		result.ReasonCode = "volume_inventory_failed"
		return result
	}
	present := map[string]bool{}
	for _, name := range names {
		present[name] = true
	}
	for _, name := range names {
		if ctx.Err() != nil {
			result.State = "partial"
			result.ReasonCode = "native_deadline"
			break
		}
		present[name] = true
		if h, ok := s.volumes[name]; ok {
			usb, err := volumeIsUSB(h)
			if err == nil && usb {
				result.Targets++
				result.Controlled++
				continue
			}
			if err != nil {
				result.Targets++
				result.State = "partial"
				result.ReasonCode = "volume_readback_unknown"
				continue
			}
			_ = windows.CloseHandle(h)
			delete(s.volumes, name)
		}
		h, err := openChannelVolume(name, 0)
		if err != nil {
			result.State = "partial"
			result.ReasonCode = "volume_identity_unknown"
			continue
		} // Never force-close another application's handles.
		usb, err := volumeIsUSB(h)
		if err != nil {
			_ = windows.CloseHandle(h)
			result.State = "partial"
			result.ReasonCode = "volume_identity_unknown"
			continue
		}
		if !usb {
			_ = windows.CloseHandle(h)
			continue
		}
		result.Targets++
		_ = windows.CloseHandle(h)
		h, err = openChannelVolume(name, windows.GENERIC_READ|windows.GENERIC_WRITE)
		if err != nil {
			result.State = "partial"
			result.ReasonCode = "volume_access_denied"
			continue
		}
		var returned uint32
		err = windows.DeviceIoControl(h, fsctlLockVolume, nil, 0, nil, 0, &returned, nil)
		if err != nil {
			_ = windows.CloseHandle(h)
			result.State = "partial"
			result.ReasonCode = "volume_busy_or_unsupported"
			continue
		}
		s.volumes[name] = h
		result.Controlled++
	}
	for name, h := range s.volumes {
		if !present[name] {
			_ = windows.CloseHandle(h)
			delete(s.volumes, name)
		}
	}
	if result.Targets == 0 && result.State == "controlled" {
		result.State = "not_present"
		result.ReasonCode = "no_current_usb_volumes"
	}
	return result
}
