package ndp

import (
"fmt"
"net"
"encoding/binary"
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
    // https://tools.ietf.org/html/rfc4861#section-4.6
    1:  "Source Link Layer Address",
    2:  "Target Link Layer Address",
    3:  "Prefix Information",
    4:  "Redirected Header",
    5:  "MTU",
    // https://tools.ietf.org/html/rfc6106#section-5
    25: "Recursive DNS Server",
    31: "DNS Search List",
}

// https://tools.ietf.org/html/rfc4861#section-4.6
type ICMPOption struct {
    Type   ICMPOptionType
    Length uint8
}

// https://tools.ietf.org/html/rfc4861#section-4.6.1
type ICMPOptionSourceLinkLayerAddress struct {
    ICMPOption
    LinkLayerAddress net.HardwareAddr
}

type ICMPOptionTargetLinkLayerAddress struct {
    ICMPOption
    LinkLayerAddress net.HardwareAddr
}

// https://tools.ietf.org/html/rfc4861#section-4.6.2
type ICMPOptionPrefixInformation struct {
    ICMPOption
    PrefixLength      uint8
    OnLink            bool
    Auto              bool
    ValidLifetime     uint32
    PreferredLifetime uint32
    Prefix            net.IP
}

func (o *ICMPOption) Marshal(proto int) ([]byte, error) {
    b := make([]byte, 8)
    b[0] ^= byte(o.Type)
    b[1] ^= byte(o.Length)
    return b, nil
}

func ParseOptions(b []byte) ([]ICMPOption, error) {
    // empty container
    var icmpOptions = []ICMPOption {}

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
                    goto cleanup
                }

                currentOption := &ICMPOptionSourceLinkLayerAddress{
                    ICMPOption:       ICMPOption{
                        Type:   optionType,
                        Length: optionLength,
                    },
                    LinkLayerAddress: b[2:8],
                }

                fmt.Printf("source address: %s\n", currentOption.LinkLayerAddress.String())

            case ICMPOptionTypeTargetLinkLayerAddress:
                if optionLength != 1 {
                    fmt.Printf("incorrect length of %d\n", optionLength)
                    goto cleanup
                }

                currentOption := &ICMPOptionTargetLinkLayerAddress{
                    ICMPOption:       ICMPOption{
                        Type:   optionType,
                        Length: optionLength,
                    },
                    LinkLayerAddress: b[2:8],
                }

                fmt.Printf("target address: %s\n", currentOption.LinkLayerAddress.String())

            case ICMPOptionTypePrefixInformation:
                if optionLength != 4 {
                    fmt.Printf("incorrect length of %d\n", optionLength)
                    goto cleanup
                }

                currentOption := &ICMPOptionPrefixInformation{
                    ICMPOption:        ICMPOption{
                        Type:   optionType,
                        Length: optionLength,
                    },
                    PrefixLength:      uint8(b[2]),
                    OnLink:            (b[3] & 0x80 > 0),
                    Auto:              (b[3] & 0x40 > 0),
                    ValidLifetime:     binary.BigEndian.Uint32(b[4:8]),
                    PreferredLifetime: binary.BigEndian.Uint32(b[8:12]),
                    Prefix:            net.IP(b[16:32]),
                }

                fmt.Printf("prefix: %s/%d, onlink: %t, auto: %t, valid: %d, preferred: %d\n", currentOption.Prefix.String(), currentOption.PrefixLength, currentOption.OnLink, currentOption.Auto, currentOption.ValidLifetime, currentOption.PreferredLifetime)

            default:
                fmt.Printf("unhandled icmp option %d\n", optionType)
        }

cleanup:
        // chop off bytes for this option
        b = b[(optionLength * 8):]
    }

    return icmpOptions, nil
}
