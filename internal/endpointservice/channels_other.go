//go:build !windows

package endpointservice

func NativeChannelsSupported() bool                        { return false }
func NewNativeChannelSystem(Config) (ChannelSystem, error) { return nil, nil }
