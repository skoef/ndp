package ndp

import (
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
