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
	m, _ := p.Marshal()
	s := fmt.Sprintf("%s, length %d  ", p.Type(), uint8(len(m)))
	s += fmt.Sprintf("who has %s\n", p.TargetAddress)
	for _, o := range p.Options {
		s += fmt.Sprintf("    %s\n", o)
	}

	return s
}

func (p *ICMPNeighborSolicitation) Marshal() ([]byte, error) {
	b := make([]byte, 8)
	// message header
	b[0] = uint8(p.Type())
	// b[1] = code, always 0
	// b[2:3] = checksum, TODO
	b = append(b, p.TargetAddress...)
	// add options
	om, err := p.optMarshal()
	if err != nil {
		return nil, err
	}

	b = append(b, om...)
	return b, nil
}
