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

	return 16 + p.optLen()
}

func (p *ICMPRouterAdvertisement) Marshal() ([]byte, error) {
	b := make([]byte, 16)
	// message header
	b[0] = uint8(p.Type())
	// b[1] = code, always 0
	// b[2:3] = checksum, TODO
	b[4] ^= byte(p.HopLimit)
	if p.ManagedAddress {
		b[5] ^= 0x80
	}
	if p.OtherStateful {
		b[5] ^= 0x40
	}
	if p.HomeAgent {
		b[5] ^= 0x20
	}
	binary.BigEndian.PutUint16(b[6:8], uint16(p.RouterLifeTime))
	binary.BigEndian.PutUint32(b[8:12], uint32(p.ReachableTime))
	binary.BigEndian.PutUint32(b[12:16], uint32(p.RetransTimer))
	// add options
	om, err := p.optMarshal()
	if err != nil {
		return nil, err
	}

	b = append(b, om...)
	return b, nil
}
