package ndp

import (
    "net"
)

// https://tools.ietf.org/html/rfc4861#section-4.3
type NeighborSolicitation struct {
    TargetAddress net.IP
    Options       []ICMPOption
}

func (p *NeighborSolicitation) Len(proto int) int {
    if p == nil {
        return 0
    }

    // TODO: fix this!!
    // doens't actually calculate anything
    return 4 + 16
}

func (p *NeighborSolicitation) Marshal(proto int) ([]byte, error) {
    b := make([]byte, 4)
    buf := append(b, p.TargetAddress...)
    return buf, nil
}
