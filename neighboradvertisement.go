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
	m, _ := p.Marshal()
	s := fmt.Sprintf("%s, length %d  ", p.Type(), uint8(len(m)))
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

func (p *ICMPNeighborAdvertisement) Marshal() ([]byte, error) {
	b := make([]byte, 8)
	// message header
	b[0] = uint8(p.Type())
	// b[1] = code, always 0
	// b[2:3] = checksum, TODO
	if p.Router {
		b[3] ^= 0x80
	}
	if p.Solicited {
		b[3] ^= 0x40
	}
	if p.Override {
		b[3] ^= 0x20
	}
	b = append(b, p.TargetAddress...)
	// add options
	om, err := p.optMarshal()
	if err != nil {
		return nil, err
	}

	b = append(b, om...)

	return b, nil
}
