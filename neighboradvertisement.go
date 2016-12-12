package ndp

import (
    "net"
)

// https://tools.ietf.org/html/rfc4861#section-4.4
type NeighborAdvertisement struct {
    Router        bool
    Solicited     bool
    Override      bool
    TargetAddress net.IP
    Options       []ICMPOption
}

func (p *NeighborAdvertisement) Len(proto int) int {
    if p == nil {
        return 0
    }

    // TODO: fix this!!
    // doens't actually calculate anything
    return 4 + 4 + 16
}

func (p *NeighborAdvertisement) Marshal(proto int) ([]byte, error) {
    b := make([]byte, 4)
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
