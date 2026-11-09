package endpointservice

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
)

type winRecoveryInterfaceRow struct {
	LUID      uint64
	Status    uint32
	Octets    uint64
	Interface nativeInterface
}
type winRecoveryAddressRow struct {
	LUID      uint64
	Addresses []netip.Prefix
}

func winRecoveryMerge(before, after []winRecoveryInterfaceRow, addresses, confirmed []winRecoveryAddressRow) ([]nativeInterface, error) {
	if len(before) != len(after) {
		return nil, errors.New("recovery interfaces changed during enumeration")
	}
	lookup := map[uint64]winRecoveryInterfaceRow{}
	for _, row := range before {
		if row.LUID == 0 || row.Interface.ID == "" {
			return nil, errors.New("unknown recovery interface identity")
		}
		if _, exists := lookup[row.LUID]; exists {
			return nil, errors.New("duplicate recovery interface identity")
		}
		lookup[row.LUID] = row
	}
	seen := map[uint64]bool{}
	for _, row := range after {
		old, exists := lookup[row.LUID]
		if !exists || seen[row.LUID] || !reflect.DeepEqual(old.Interface, row.Interface) {
			return nil, errors.New("recovery interfaces changed during enumeration")
		}
		seen[row.LUID] = true
	}

	canonical := func(rows []winRecoveryAddressRow) (map[uint64][]netip.Prefix, error) {
		addr := map[uint64][]netip.Prefix{}
		for _, row := range rows {
			if _, exists := lookup[row.LUID]; !exists {
				return nil, errors.New("recovery addresses have unknown interface")
			}
			if _, exists := addr[row.LUID]; exists {
				return nil, errors.New("duplicate recovery address scope")
			}
			var prefixes []netip.Prefix
			for _, p := range row.Addresses {
				if !p.IsValid() {
					return nil, errors.New("invalid recovery address")
				}
				prefixes = append(prefixes, p)
			}
			slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
				if n := a.Addr().Compare(b.Addr()); n != 0 {
					return n
				}
				return a.Bits() - b.Bits()
			})
			addr[row.LUID] = slices.Compact(prefixes)
		}
		return addr, nil
	}
	addr, err := canonical(addresses)
	if err != nil {
		return nil, err
	}
	second, err := canonical(confirmed)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(addr, second) {
		return nil, errors.New("recovery interface addresses changed during enumeration")
	}

	out := make([]nativeInterface, 0, len(before))
	for _, row := range before {
		iface := row.Interface
		iface.Addresses = slices.Clone(addr[row.LUID])
		out = append(out, iface)
	}
	return out, nil
}
func winRecoverySnapshot(ctx context.Context, s nativeSession, validate func(context.Context, nativeSession, bool) error, interfaces func(context.Context) ([]nativeInterface, error)) (nativeSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nativeSnapshot{}, err
	}
	if s == nil {
		return nativeSnapshot{}, errors.New("missing recovery session")
	}
	if err := validate(ctx, s, true); err != nil {
		return nativeSnapshot{}, err
	}
	all, err := interfaces(ctx)
	if err != nil {
		return nativeSnapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return nativeSnapshot{}, err
	}
	if err := validate(ctx, s, true); err != nil {
		return nativeSnapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return nativeSnapshot{}, err
	}
	owned := make([]nativeInterface, len(all))
	for i, iface := range all {
		iface.Addresses = slices.Clone(iface.Addresses)
		owned[i] = iface
	}
	return nativeSnapshot{Interfaces: owned}, nil
}
