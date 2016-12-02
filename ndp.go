package ndp

import "encoding/binary"

func ParseRouterAdvertisement(b []byte) (*RouterAdvertisement, error) {
    p := &RouterAdvertisement{
        HopLimit:       uint8(b[0]),
        ManagedAddress: false,
        OtherStateful:  false,
        HomeAgent:      false,
        RouterLifeTime: binary.BigEndian.Uint16(b[2:4]),
        ReachableTime:  binary.BigEndian.Uint32(b[4:8]),
        RetransTimer:   binary.BigEndian.Uint32(b[8:12]),
    }

    // parse flags
    if b[1] & 0x80 > 0 {
        p.ManagedAddress = true
    }
    if b[1] & 0x40 > 0 {
        p.OtherStateful = true
    }
    if b[1] & 0x20 > 0 {
        p.HomeAgent = true
    }
    return p, nil
}

func ParseRouterSolicitation(b []byte) (*RouterSolicitation, error) {
    p := &RouterSolicitation{

    }

    return p, nil
}

func ParseNeighborAdvertisement(b []byte) (*NeighborAdvertisement, error) {
    p := &NeighborAdvertisement{
       TargetAddress: b[4:20],
    }

    return p, nil
}

func ParseNeighborSolicitation(b []byte) (*NeighborSolicitation, error) {
    p := &NeighborSolicitation{
       TargetAddress: b[4:20],
    }

    return p, nil
}
