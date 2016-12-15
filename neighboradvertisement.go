package ndp

import (
	"fmt"
	"net"
)

// As defined in https://tools.ietf.org/html/rfc4861#section-4.4
type ICMPNeighborAdvertisement struct {
	*ICMPBase
	Router        bool
	Solicited     bool
	Override      bool
	TargetAddress net.IP
}

func (p *ICMPNeighborAdvertisement) String() string {
	// tgt is 2a01:7c8:aaaa:3:ba1d::3, Flags [solicited]
	s := fmt.Sprintf("%s, length %d  ", p.Type(), p.Len())
	s += fmt.Sprintf("tgt is %s, ", p.TargetAddress)
	s += "Flags ["
	if p.Router {
		s += "router "
	}
	if p.Solicited {
		s += "solicited "
	}
	if p.Override {
		s += "override"
	}
	s += "]\n"
	for _, o := range p.Options {
		s += fmt.Sprintf("    %s\n", o)
	}

	return s
}

func (p *ICMPNeighborAdvertisement) Len() uint8 {
	if p == nil {
		return 0
	}

	// TODO: fix this!!
	// doens't actually calculate anything
	return 4 + 4 + 16
}

func (p *ICMPNeighborAdvertisement) Marshal() ([]byte, error) {
	b := make([]byte, p.Len())
	if p.Router {
		b[0] ^= 0x80
	}
	if p.Solicited {
		b[0] ^= 0x40
	}
	if p.Override {
		b[0] ^= 0x20
	}

	buf := append(b, p.TargetAddress...)

	return buf, nil
}
