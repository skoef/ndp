package ndp

import (
    "encoding/binary"
    "errors"
)

func ParseRouterAdvertisement(b []byte) (*RouterAdvertisement, error) {
    if len(b) < 4 {
        return nil, errors.New("message too short")
    }

    // first 4 bytes is ICMPv6 header
    p := &RouterAdvertisement{
        HopLimit:       uint8(b[4]),
        ManagedAddress: false,
        OtherStateful:  false,
        HomeAgent:      false,
        RouterLifeTime: binary.BigEndian.Uint16(b[6:8]),
        ReachableTime:  binary.BigEndian.Uint32(b[8:12]),
        RetransTimer:   binary.BigEndian.Uint32(b[12:16]),
    }

    // parse flags
    if b[5] & 0x80 > 0 {
        p.ManagedAddress = true
    }
    if b[5] & 0x40 > 0 {
        p.OtherStateful = true
    }
    if b[5] & 0x20 > 0 {
        p.HomeAgent = true
    }

    return p, nil
}

func ParseRouterSolicitation(b []byte) (*RouterSolicitation, error) {
    if len(b) < 4 {
        return nil, errors.New("message too short")
    }

    // first 4 bytes is ICMPv6 header
    p := &RouterSolicitation{

    }

    return p, nil
}

func ParseNeighborAdvertisement(b []byte) (*NeighborAdvertisement, error) {
    if len(b) < 4 {
        return nil, errors.New("message too short")
    }

    // first 4 bytes is ICMPv6 header
    p := &NeighborAdvertisement{
       TargetAddress: b[8:24],
    }

    return p, nil
}

func ParseNeighborSolicitation(b []byte) (*NeighborSolicitation, error) {
    if len(b) < 4 {
        return nil, errors.New("message too short")
    }

    // first 4 bytes is ICMPv6 header
    p := &NeighborSolicitation{
       TargetAddress: b[8:24],
    }

    return p, nil
}
