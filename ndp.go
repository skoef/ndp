package ndp

import (
    "encoding/binary"
    "errors"
    "fmt"
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

    if len(b) > 16 {
        fmt.Printf("RA has options: %d bytes\n", len(b) - 16)

        options, err := ParseOptions(b[16:])
        if err != nil {
            fmt.Errorf("failed parsing options: %s", err)
        } else {
            p.Options = options
        }
    }

    return p, nil
}

func ParseRouterSolicitation(b []byte) (*RouterSolicitation, error) {
    if len(b) < 4 {
        return nil, errors.New("message too short")
    }

    // first 4 bytes is ICMPv6 header
    p := &RouterSolicitation{}

    if len(b) > 8 {
        fmt.Printf("RS has options: %d bytes\n", len(b) - 8)

        options, err := ParseOptions(b[8:])
        if err != nil {
            fmt.Errorf("failed parsing options: %s", err)
        } else {
            p.Options = options
        }
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

    // parse flags
    if b[4] & 0x80 > 0 {
        p.Router = true
    }
    if b[4] & 0x40 > 0 {
        p.Solicited = true
    }
    if b[4] & 0x20 > 0 {
        p.Override = true
    }

    if len(b) > 24 {
        fmt.Printf("NA has options: %d bytes\n", len(b) - 24)

        options, err := ParseOptions(b[24:])
        if err != nil {
            fmt.Printf("failed parsing options")
        } else {
            p.Options = options
        }
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

    if len(b) > 24 {
        fmt.Printf("NS has options: %d bytes\n", len(b) - 24)

        options, err := ParseOptions(b[24:])
        if err != nil {
            fmt.Printf("failed parsing options")
        } else {
            p.Options = options
        }
    }

    return p, nil
}
