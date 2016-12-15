package ndp

import (
	"encoding/binary"
	"fmt"
)

// As defined in https://tools.ietf.org/html/rfc4861#section-4.2
type ICMPRouterAdvertisement struct {
	*ICMPBase
	HopLimit       uint8
	ManagedAddress bool
	OtherStateful  bool
	HomeAgent      bool
	RouterLifeTime uint16
	ReachableTime  uint32
	RetransTimer   uint32
}

func (p *ICMPRouterAdvertisement) String() string {
	s := fmt.Sprintf("%s, length %d\n  ", p.Type(), p.Len())
	s += fmt.Sprintf("hop limit %d, ", p.HopLimit)
	f := []string{}
	if p.ManagedAddress {
		f = append(f, "managed")
	}
	if p.OtherStateful {
		f = append(f, "other stateful")
	}
	if p.HomeAgent {
		f = append(f, "home agent")
	}
	s += fmt.Sprintf("Flags %s, ", f)
	s += fmt.Sprintf("router lifetime %ds, ", p.RouterLifeTime)
	s += fmt.Sprintf("reachable time %ds, ", p.ReachableTime)
	s += fmt.Sprintf("retrans time %ds\n", p.RetransTimer)
	for _, o := range p.Options {
		s += fmt.Sprintf("    %s\n", o)
	}

	return s
}

func (p *ICMPRouterAdvertisement) Len() uint8 {
	if p == nil {
		return 0
	}

	// TODO: fix this!!
	// doens't actually calculate anything
	return 12
}

func (p *ICMPRouterAdvertisement) Marshal() ([]byte, error) {
	b := make([]byte, p.Len())
	b[0] ^= byte(p.HopLimit)
	if p.ManagedAddress {
		b[1] ^= 0x80
	}
	if p.OtherStateful {
		b[1] ^= 0x40
	}
	if p.HomeAgent {
		b[1] ^= 0x20
	}
	binary.BigEndian.PutUint16(b[2:4], uint16(p.RouterLifeTime))
	binary.BigEndian.PutUint32(b[4:8], uint32(p.ReachableTime))
	binary.BigEndian.PutUint32(b[8:12], uint32(p.RetransTimer))
	return b, nil
}
