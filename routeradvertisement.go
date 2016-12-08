package ndp

import "encoding/binary"

// https://tools.ietf.org/html/rfc4861#section-4.2
type RouterAdvertisement struct {
    HopLimit       uint8
    ManagedAddress bool
    OtherStateful  bool
    HomeAgent      bool
    RouterLifeTime uint16
    ReachableTime  uint32
    RetransTimer   uint32
    Options        []ICMPOption
}

func (p *RouterAdvertisement) Len(proto int) int {
    if p == nil {
        return 0
    }

    // TODO: fix this!!
    // doens't actually calculate anything
    return 12
}

func (p *RouterAdvertisement) Marshal(proto int) ([]byte, error) {
    b := make([]byte, p.Len(0))
    b[0] ^= byte(p.HopLimit)
    if p.ManagedAddress {
        b[1] ^= 0x80
    }
    if p.OtherStateful {
        b[1] ^= 0x40
    }
    if p.HomeAgent {
        b[1] ^= 0x20
    }
    binary.BigEndian.PutUint16(b[2:4], uint16(p.RouterLifeTime))
    binary.BigEndian.PutUint32(b[4:8], uint32(p.ReachableTime))
    binary.BigEndian.PutUint32(b[8:12], uint32(p.RetransTimer))
    return b, nil
}
