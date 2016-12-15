package ndp

import (
	"fmt"
	"net"
)

// As defined in https://tools.ietf.org/html/rfc4861#section-4.3
type ICMPNeighborSolicitation struct {
	*ICMPBase
	TargetAddress net.IP
}

func (p *ICMPNeighborSolicitation) String() string {
	s := fmt.Sprintf("%s, length %d  ", p.Type(), p.Len())
	s += fmt.Sprintf("who has %s\n", p.TargetAddress)
	for _, o := range p.Options {
		s += fmt.Sprintf("    %s\n", o)
	}

	return s
}

func (p *ICMPNeighborSolicitation) Len() uint8 {
	if p == nil {
		return 0
	}

	// TODO: fix this!!
	// doens't actually calculate anything
	return 4 + 16
}

func (p *ICMPNeighborSolicitation) Marshal() ([]byte, error) {
	b := make([]byte, p.Len())
	buf := append(b, p.TargetAddress...)
	return buf, nil
}
