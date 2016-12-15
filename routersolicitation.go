package ndp

// As defined in https://tools.ietf.org/html/rfc4861#section-4.1
type ICMPRouterSolicitation struct {
	*ICMPBase
}

func (p *ICMPRouterSolicitation) Len() uint8 {
	if p == nil {
		return 0
	}

	// TODO: fix this!!
	// calculate options
	return 4
}

func (p *ICMPRouterSolicitation) Marshal() ([]byte, error) {
	b := make([]byte, p.Len())
	return b, nil
}
