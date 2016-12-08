package ndp

import (
    "encoding/binary"
    "errors"
    "fmt"
    "net"
)

type ICMPOptionType int

const (
    ICMPOptionTypeSourceLinkLayerAddress ICMPOptionType = 1
    ICMPOptionTypeTargetLinkLayerAddress ICMPOptionType = 2
    ICMPOptionTypePrefixInformation      ICMPOptionType = 3
    ICMPOptionTypeRedirectedHeader       ICMPOptionType = 4
    ICMPOptionTypeMTU                    ICMPOptionType = 5
    ICMPOptionTypeRecursiveDNSServer     ICMPOptionType = 25
    ICMPOptionTypeDNSSearchList          ICMPOptionType = 31
)

var icmpOptionTypes = map[ICMPOptionType]string {
    1:  "Source Link Layer Address",
    2:  "Target Link Layer Address",
    3:  "Prefix Information",
    4:  "Redirected Header",
    5:  "MTU",
    25: "Recursive DNS Server",
    31: "DNS Search List",
}

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
        fmt.Printf("RA has options: %d\n", len(b) - 16)

        b = b[16:]
OptionParser:
        for {
            if len(b) < 8 {
                fmt.Printf("options has only %d length left, done parsing\n", len(b))
                break
            }

            optionType := ICMPOptionType(b[0])
            optionLength := uint8(b[1])

            switch optionType {
                case ICMPOptionTypeSourceLinkLayerAddress:
                    if optionLength != 1 {
                        fmt.Printf("incorrect length of %d\n", optionLength)
                        continue
                    }

                    var mac net.HardwareAddr = b[2:8]
                    fmt.Printf("source address: %s\n", mac.String())

                    b = b[8:]

                case ICMPOptionTypeTargetLinkLayerAddress:
                    if optionLength != 1 {
                        fmt.Printf("incorrect length of %d\n", optionLength)
                        continue
                    }

                    var mac net.HardwareAddr = b[2:8]
                    fmt.Printf("target address: %s\n", mac.String())

                    b = b[8:]

                case ICMPOptionTypePrefixInformation:
                    if optionLength != 4 {
                        fmt.Printf("incorrect length of %d\n", optionLength)
                        continue
                    }

                    prefixLength := uint8(b[2])
                    onLink := (b[3] & 0x80 > 0)
                    AAC := (b[3] & 0x40 > 0)
                    validLifetime := binary.BigEndian.Uint32(b[4:8])
                    preferredLifetime := binary.BigEndian.Uint32(b[8:12])
                    prefix := net.IP(b[16:32])
                    fmt.Printf("prefix: %s/%d, onlink: %t, aac: %t, valid: %d, preferred: %d\n", prefix.String(), prefixLength, onLink, AAC, validLifetime, preferredLifetime)

                    b = b[32:]

                default:
                    fmt.Printf("unhandled icmp option %d\n", optionType)
                    switch optionLength {
                        case 1:
                            b = b[8:]
                        case 2:
                            b = b[16:]
                        case 5:
                            b = b[40:]
                        default:
                            fmt.Printf("unhandled option length: %d\n", optionLength)
                            break OptionParser
                    }
            }

            fmt.Printf("found option %s (%d) with length %d\n", icmpOptionTypes[optionType], optionType, optionLength)
        }
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
