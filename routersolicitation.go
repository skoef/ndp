package ndp

import "fmt"

// As defined in https://tools.ietf.org/html/rfc4861#section-4.1
type ICMPRouterSolicitation struct {
	*ICMPBase
}

func (p *ICMPRouterSolicitation) String() string {
	s := fmt.Sprintf("%s, length %d\n  ", p.Type(), p.Len())
	for _, o := range p.Options {
		s += fmt.Sprintf("    %s\n", o)
	}

	return s
}

func (p *ICMPRouterSolicitation) Len() uint8 {
	if p == nil {
		return 0
	}

	return 1 + p.optLen()
}

func (p *ICMPRouterSolicitation) Marshal() ([]byte, error) {
	b := make([]byte, 8)
	// message header
	b[0] = uint8(p.Type())
	// b[1] = code, always 0
	// b[2:3] = checksum, TODO
	// add options
	om, err := p.optMarshal()
	if err != nil {
		return nil, err
	}

	b = append(b, om...)
	return b, nil
}
