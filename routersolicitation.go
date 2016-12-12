package ndp

// https://tools.ietf.org/html/rfc4861#section-4.1
type RouterSolicitation struct {
    // Reserved uint32
    Options []ICMPOption
}

func (p *RouterSolicitation) Len(proto int) int {
    if p == nil {
        return 0
    }

    // TODO: fix this!!
    // calculate options
    return 4
}

func (p *RouterSolicitation) Marshal(proto int) ([]byte, error) {
    b := make([]byte, p.Len(0))
    return b, nil
}
