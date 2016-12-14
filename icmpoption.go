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
type ICMPOption interface {
    Len()        uint8
    Marshal()    ([]byte, error)
}

// https://tools.ietf.org/html/rfc4861#section-4.6.1
type ICMPOptionSourceLinkLayerAddress struct {
    Type             ICMPOptionType
    Length           uint8
    LinkLayerAddress net.HardwareAddr
}

type ICMPOptionTargetLinkLayerAddress struct {
    Type             ICMPOptionType
    Length           uint8
    LinkLayerAddress net.HardwareAddr
}

// https://tools.ietf.org/html/rfc4861#section-4.6.2
type ICMPOptionPrefixInformation struct {
    Type              ICMPOptionType
    Length            uint8
    PrefixLength      uint8
    OnLink            bool
    Auto              bool
    ValidLifetime     uint32
    PreferredLifetime uint32
    Prefix            net.IP
}

// https://tools.ietf.org/html/rfc6106#section-5.1
type ICMPOptionRecursiveDNSServer struct {
    Type     ICMPOptionType
    Length   uint8
    Lifetime uint32
    Servers  []net.IP
}

// https://tools.ietf.org/html/rfc6106#section-5.2
type ICMPOptionDNSSearchList struct {
    Type        ICMPOptionType
    Length      uint8
    Lifetime    uint32
    DomainNames []string
}

func ParseOptions(b []byte) ([]ICMPOption, error) {
    // empty container
    var icmpOptions = []ICMPOption {}

    for {
        // left over bytes are less than minimum option length
        if len(b) < 8 {
            break
        }

        optionType := ICMPOptionType(b[0])
        optionLength := uint8(b[1])
        var currentOption ICMPOption

        switch optionType {
            case ICMPOptionTypeSourceLinkLayerAddress:
                if optionLength != 1 {
                    fmt.Printf("incorrect length of %d\n", optionLength)
                    goto cleanup
                }

                currentOption := &ICMPOptionSourceLinkLayerAddress{
                    Type:             optionType,
                    Length:           optionLength,
                    LinkLayerAddress: b[2:8],
                }

                fmt.Printf("source address: %s\n", currentOption.LinkLayerAddress.String())

            case ICMPOptionTypeTargetLinkLayerAddress:
                if optionLength != 1 {
                    fmt.Printf("incorrect length of %d\n", optionLength)
                    goto cleanup
                }

                currentOption := &ICMPOptionTargetLinkLayerAddress{
                    Type:             optionType,
                    Length:           optionLength,
                    LinkLayerAddress: b[2:8],
                }

                fmt.Printf("target address: %s\n", currentOption.LinkLayerAddress.String())

            case ICMPOptionTypePrefixInformation:
                if optionLength != 4 {
                    fmt.Printf("incorrect length of %d\n", optionLength)
                    goto cleanup
                }

                currentOption := &ICMPOptionPrefixInformation{
                    Type:              optionType,
                    Length:            optionLength,
                    PrefixLength:      uint8(b[2]),
                    OnLink:            (b[3] & 0x80 > 0),
                    Auto:              (b[3] & 0x40 > 0),
                    ValidLifetime:     binary.BigEndian.Uint32(b[4:8]),
                    PreferredLifetime: binary.BigEndian.Uint32(b[8:12]),
                    Prefix:            net.IP(b[16:32]),
                }

                fmt.Printf("prefix: %s/%d, onlink: %t, auto: %t, valid: %d, preferred: %d\n", currentOption.Prefix.String(), currentOption.PrefixLength, currentOption.OnLink, currentOption.Auto, currentOption.ValidLifetime, currentOption.PreferredLifetime)

            case ICMPOptionTypeRecursiveDNSServer:
                if optionLength < 3 {
                    fmt.Printf("incorrect length of %d for option 25\n", optionLength)
                    goto cleanup
                }

                currentOption := &ICMPOptionRecursiveDNSServer{
                    Type:       optionType,
                    Length:     optionLength,
                    Lifetime:   binary.BigEndian.Uint32(b[4:8]),
                }

                for i := 8; i < (int(optionLength) * 8); i += 16 {
                    currentOption.Servers = append(currentOption.Servers, net.IP(b[i:(i+16)]))
                }

                fmt.Printf("lifetime: %d, servers: %s\n", currentOption.Lifetime, currentOption.Servers)

            case ICMPOptionTypeDNSSearchList:
                if optionLength < 4 {
                    fmt.Printf("incorrect length of %d for option %d\n", optionLength, optionType)
                    goto cleanup
                }

                currentOption := &ICMPOptionDNSSearchList{
                    Type:     optionType,
                    Length:   optionLength,
                    Lifetime: binary.BigEndian.Uint32(b[4:8]),
                }

                for i := 8; i <(int(optionLength) * 8); i += 24 {
                    currentOption.DomainNames = append(currentOption.DomainNames, absDomainName(b[i:(i+24)]))
                }

                fmt.Printf("lifetime: %d, domains: %s\n", currentOption.Lifetime, currentOption.DomainNames)

            default:
                fmt.Printf("unhandled icmp option: %s (%d) (len: %d)\n", icmpOptionTypes[optionType], optionType, optionLength)
                goto cleanup
        }

        // add new option to array of options
        icmpOptions = append(icmpOptions, currentOption)

cleanup:
        // chop off bytes for this option
        b = b[(optionLength * 8):]
    }

    return icmpOptions, nil
}

// inspired by golang.org/net/dnsclient.go's absDomainName
func absDomainName(b []byte) string {
    name := ""
    start := 0
    for {
        length := int(b[start])
        if length > 0 {
            name += string(b[start:(start+length+1)]) + "."
        }

        start += (length + 1)
        if start >= len(b) {
            break
        }
    }

    return name
}
