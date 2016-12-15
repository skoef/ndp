package ndp

import (
	"net"
)

// As defined in https://tools.ietf.org/html/rfc4861#section-4.3
type ICMPNeighborSolicitation struct {
	*ICMPBase
	TargetAddress net.IP
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
