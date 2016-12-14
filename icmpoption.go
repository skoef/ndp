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

// Len implements the Len method of ICMPOption interface.
func (o *ICMPOptionSourceLinkLayerAddress) Len() uint8 {
    if o == nil {
        return 0
    }

    return 1
}

type ICMPOptionTargetLinkLayerAddress struct {
    Type             ICMPOptionType
    Length           uint8
    LinkLayerAddress net.HardwareAddr
}

// Len implements the Len method of ICMPOption interface.
func (o *ICMPOptionTargetLinkLayerAddress) Len() uint8 {
    if o == nil {
        return 0
    }

    return 1
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

// Len implements the Len method of ICMPOption interface.
func (o *ICMPOptionPrefixInformation) Len() uint8 {
    if o == nil {
        return 0
    }

    return 4
}

// https://tools.ietf.org/html/rfc4861#section-4.6.4
type ICMPOptionMTU struct {
    Type   ICMPOptionType
    Length uint8
    MTU    uint32
}

// Len implements the Len method of ICMPOption interface.
func (o *ICMPOptionMTU) Len() uint8 {
    if o == nil {
        return 0
    }

    return 1
}

// https://tools.ietf.org/html/rfc6106#section-5.1
type ICMPOptionRecursiveDNSServer struct {
    Type     ICMPOptionType
    Length   uint8
    Lifetime uint32
    Servers  []net.IP
}

// Len implements the Len method of ICMPOption interface.
func (o *ICMPOptionRecursiveDNSServer) Len() uint8 {
    if o == nil {
        return 0
    }

    return 1 + uint8(len(o.Servers) * 2)
}

// https://tools.ietf.org/html/rfc6106#section-5.2
type ICMPOptionDNSSearchList struct {
    Type        ICMPOptionType
    Length      uint8
    Lifetime    uint32
    DomainNames []string
}

// Len implements the Len method of ICMPOption interface.
func (o *ICMPOptionDNSSearchList) Len() uint8 {
    if o == nil {
        return 0
    }

    return 1 + uint8(len(o.DomainNames) * 3)
}

func parseOptions(b []byte) ([]ICMPOption, error) {
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
                    return nil, fmt.Errorf("option %s (%d) too short: %d should be 1", icmpOptionTypes[optionType], optionType, optionLength)
                }

                currentOption := &ICMPOptionSourceLinkLayerAddress{
                    Type:             optionType,
                    Length:           optionLength,
                    LinkLayerAddress: b[2:8],
                }

                if optionLength != currentOption.Len() {
                    return nil, fmt.Errorf("length mismatch while parsing %s: %d should be %d", icmpOptionTypes[optionType], currentOption.Len(), optionLength)
                }

                fmt.Printf("source address: %s\n", currentOption.LinkLayerAddress.String())

            case ICMPOptionTypeTargetLinkLayerAddress:
                if optionLength != 1 {
                    return nil, fmt.Errorf("option %s (%d) too short: %d should be 1", icmpOptionTypes[optionType], optionType, optionLength)
                }

                currentOption := &ICMPOptionTargetLinkLayerAddress{
                    Type:             optionType,
                    Length:           optionLength,
                    LinkLayerAddress: b[2:8],
                }

                if optionLength != currentOption.Len() {
                    return nil, fmt.Errorf("length mismatch while parsing %s: %d should be %d", icmpOptionTypes[optionType], currentOption.Len(), optionLength)
                }

                fmt.Printf("target address: %s\n", currentOption.LinkLayerAddress.String())

            case ICMPOptionTypePrefixInformation:
                if optionLength != 4 {
                    return nil, fmt.Errorf("option %s (%d) too short: %d should be 4", icmpOptionTypes[optionType], optionType, optionLength)
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

                if optionLength != currentOption.Len() {
                    return nil, fmt.Errorf("length mismatch while parsing %s: %d should be %d", icmpOptionTypes[optionType], currentOption.Len(), optionLength)
                }


                fmt.Printf("prefix: %s/%d, onlink: %t, auto: %t, valid: %d, preferred: %d\n", currentOption.Prefix.String(), currentOption.PrefixLength, currentOption.OnLink, currentOption.Auto, currentOption.ValidLifetime, currentOption.PreferredLifetime)

            case ICMPOptionTypeMTU:
                if optionLength != 1 {
                    return nil, fmt.Errorf("option %s (%d) too short: %d should be 1", icmpOptionTypes[optionType], optionType, optionLength)
                }

                currentOption := &ICMPOptionMTU{
                    Type:   optionType,
                    Length: optionLength,
                    MTU:    binary.BigEndian.Uint32(b[4:8]),
                }

                if optionLength != currentOption.Len() {
                    return nil, fmt.Errorf("length mismatch while parsing %s: %d should be %d", icmpOptionTypes[optionType], currentOption.Len(), optionLength)
                }

                fmt.Printf("MTU: %d\n", currentOption.MTU)

            case ICMPOptionTypeRecursiveDNSServer:
                if optionLength < 3 {
                    return nil, fmt.Errorf("option %s (%d) too short: %d should at least be 3", icmpOptionTypes[optionType], optionType, optionLength)
                }

                currentOption := &ICMPOptionRecursiveDNSServer{
                    Type:       optionType,
                    Length:     optionLength,
                    Lifetime:   binary.BigEndian.Uint32(b[4:8]),
                }

                for i := 8; i < (int(optionLength) * 8); i += 16 {
                    currentOption.Servers = append(currentOption.Servers, net.IP(b[i:(i+16)]))
                }

                if optionLength != currentOption.Len() {
                    return nil, fmt.Errorf("length mismatch while parsing %s: %d should be %d", icmpOptionTypes[optionType], currentOption.Len(), optionLength)
                }

                fmt.Printf("lifetime: %d, servers: %s\n", currentOption.Lifetime, currentOption.Servers)

            case ICMPOptionTypeDNSSearchList:
                if optionLength < 4 {
                    return nil, fmt.Errorf("option %s (%d) too short: %d should at least be 4", icmpOptionTypes[optionType], optionType, optionLength)
                }

                currentOption := &ICMPOptionDNSSearchList{
                    Type:     optionType,
                    Length:   optionLength,
                    Lifetime: binary.BigEndian.Uint32(b[4:8]),
                }

                for i := 8; i <(int(optionLength) * 8); i += 24 {
                    currentOption.DomainNames = append(currentOption.DomainNames, absDomainName(b[i:(i+24)]))
                }

                if optionLength != currentOption.Len() {
                    return nil, fmt.Errorf("length mismatch while parsing %s: %d should be %d", icmpOptionTypes[optionType], currentOption.Len(), optionLength)
                }

                fmt.Printf("lifetime: %d, domains: %s\n", currentOption.Lifetime, currentOption.DomainNames)

            default:
                return nil, fmt.Errorf("unhandled ICMPv6 option type %d", optionType)
        }

        // add new option to array of options
        icmpOptions = append(icmpOptions, currentOption)

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
