package ndp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// ICMPOptions is a type wrapper for a slice of ICMPOptions
type ICMPOptions []ICMPOption

// Marshal is a helper function of ICMPOptions and returns marshalled results
// for all ICMPOptions or error when there is one
func (opts ICMPOptions) Marshal() ([]byte, error) {
	var b []byte
	for _, o := range opts {
		m, err := o.Marshal()
		if err != nil {
			return nil, err
		}

		b = append(b, m...)
	}

	return b, nil
}

// ICMPOptionType describes ICMPv6 types
type ICMPOptionType int

// ICMPv6 Neighbor discovery types as described in RFC4861, RFC3971, RFC6106
const (
	_ ICMPOptionType = iota
	// RFC4861
	ICMPOptionTypeSourceLinkLayerAddress
	ICMPOptionTypeTargetLinkLayerAddress
	ICMPOptionTypePrefixInformation
	_
	ICMPOptionTypeMTU
	// RFC3971
	ICMPOptionTypeNonce ICMPOptionType = 14
	// RFC6106
	ICMPOptionTypeRecursiveDNSServer ICMPOptionType = 25
	ICMPOptionTypeDNSSearchList      ICMPOptionType = 31
)

func (t ICMPOptionType) String() string {
	switch t {
	case ICMPOptionTypeSourceLinkLayerAddress:
		return "source link-layer address"
	case ICMPOptionTypeTargetLinkLayerAddress:
		return "target link-layer address"
	case ICMPOptionTypePrefixInformation:
		return "prefix info"
	case ICMPOptionTypeMTU:
		return "mtu"
	case ICMPOptionTypeNonce:
		return "nonce"
	case ICMPOptionTypeRecursiveDNSServer:
		return "rdnss"
	case ICMPOptionTypeDNSSearchList:
		return "dnssl"
	default:
		return "<nil>"
	}
}

type ICMPOption interface {
	String() string
	Len() uint8
	Marshal() ([]byte, error)
	Type() ICMPOptionType
}

func NewICMPOption(optionType ICMPOptionType) ICMPOption {
	switch optionType {
	case ICMPOptionTypeSourceLinkLayerAddress:
		return &ICMPOptionSourceLinkLayerAddress{
			ICMPOptionBase: &ICMPOptionBase{
				optionType: ICMPOptionTypeSourceLinkLayerAddress,
			},
		}

	case ICMPOptionTypeTargetLinkLayerAddress:
		return &ICMPOptionTargetLinkLayerAddress{
			ICMPOptionBase: &ICMPOptionBase{
				optionType: ICMPOptionTypeTargetLinkLayerAddress,
			},
		}

	case ICMPOptionTypePrefixInformation:
		return &ICMPOptionPrefixInformation{
			ICMPOptionBase: &ICMPOptionBase{
				optionType: ICMPOptionTypePrefixInformation,
			},
		}

	case ICMPOptionTypeMTU:
		return &ICMPOptionMTU{
			ICMPOptionBase: &ICMPOptionBase{
				optionType: ICMPOptionTypeMTU,
			},
		}

	case ICMPOptionTypeNonce:
		return &ICMPOptionNonce{
			ICMPOptionBase: &ICMPOptionBase{
				optionType: ICMPOptionTypeNonce,
			},
		}

	case ICMPOptionTypeRecursiveDNSServer:
		return &ICMPOptionRecursiveDNSServer{
			ICMPOptionBase: &ICMPOptionBase{
				optionType: ICMPOptionTypeRecursiveDNSServer,
			},
		}

	case ICMPOptionTypeDNSSearchList:
		return &ICMPOptionDNSSearchList{
			ICMPOptionBase: &ICMPOptionBase{
				optionType: ICMPOptionTypeDNSSearchList,
			},
		}

	default:
		return nil
	}
}

type ICMPOptionBase struct {
	optionType ICMPOptionType
}

func (o *ICMPOptionBase) Type() ICMPOptionType {
	return o.optionType
}

// struct for parsing unknown/unhandled options
type ICMPOptionUnknown struct {
	optionLength uint8
	optionType   ICMPOptionType
	body         []byte
}

func (o *ICMPOptionUnknown) String() string {
	s := fmt.Sprintf("unknown option (%d), length %d (%d)", o.optionType, (o.optionLength * 8), o.optionLength)

	return s
}

func (o *ICMPOptionUnknown) Len() uint8 {
	return o.optionLength
}

func (o *ICMPOptionUnknown) Marshal() ([]byte, error) {
	b := make([]byte, 2)
	b[0] = uint8(o.optionType)
	b[1] = o.optionLength

	b = append(b, o.body...)
	return b, nil
}

func (o *ICMPOptionUnknown) Type() ICMPOptionType {
	return o.optionType
}

// As defined in https://tools.ietf.org/html/rfc4861#section-4.6.1
type ICMPOptionSourceLinkLayerAddress struct {
	*ICMPOptionBase
	LinkLayerAddress net.HardwareAddr
}

// String implements the String method of ICMPOption interface.
func (o *ICMPOptionSourceLinkLayerAddress) String() string {
	s := fmt.Sprintf("%s option (%d), ", o.Type(), o.Type())
	s += fmt.Sprintf("length %d (%d)", (o.Len() * 8), o.Len())
	s += fmt.Sprintf(": %s", o.LinkLayerAddress)

	return s
}

// Len implements the Len method of ICMPOption interface.
func (o *ICMPOptionSourceLinkLayerAddress) Len() uint8 {
	if o == nil {
		return 0
	}

	// Source Link-Layer Address options' length
	// depends on the length of the link-layer address
	// but since we define net.HardwareAddr as its type
	// in the struct, the length is always the same
	return 1
}

// Marshal implements the Marshal method of ICMPOption interface.
func (o *ICMPOptionSourceLinkLayerAddress) Marshal() ([]byte, error) {
	// option header
	b := make([]byte, 2)
	b[0] = byte(o.Type())
	b[1] = byte(o.Len())
	// option fields
	b = append(b, o.LinkLayerAddress...)

	return b, nil
}

type ICMPOptionTargetLinkLayerAddress struct {
	*ICMPOptionBase
	LinkLayerAddress net.HardwareAddr
}

// String implements the String method of ICMPOption interface.
func (o *ICMPOptionTargetLinkLayerAddress) String() string {
	s := fmt.Sprintf("%s option (%d), ", o.Type(), o.Type())
	s += fmt.Sprintf("length %d (%d)", (o.Len() * 8), o.Len())
	s += fmt.Sprintf(": %s", o.LinkLayerAddress)

	return s
}

// Len implements the Len method of ICMPOption interface.
func (o *ICMPOptionTargetLinkLayerAddress) Len() uint8 {
	if o == nil {
		return 0
	}

	// Target Link-Layer Address options' length
	// depends on the length of the link-layer address
	// but since we define net.HardwareAddr as its type
	// in the struct, the length is always 1
	return 1
}

// Marshal implements the Marshal method of ICMPOption interface.
func (o *ICMPOptionTargetLinkLayerAddress) Marshal() ([]byte, error) {
	b := make([]byte, 2)
	// option header
	b[0] = byte(o.Type())
	b[1] = byte(o.Len())
	// option fields
	b = append(b, o.LinkLayerAddress...)

	return b, nil
}

// As defined in https://tools.ietf.org/html/rfc4861#section-4.6.2
type ICMPOptionPrefixInformation struct {
	*ICMPOptionBase
	PrefixLength      uint8
	OnLink            bool
	Auto              bool
	ValidLifetime     uint32
	PreferredLifetime uint32
	Prefix            net.IP
}

// String implements the String method of ICMPOption interface.
func (o *ICMPOptionPrefixInformation) String() string {
	s := fmt.Sprintf("%s option (%d), ", o.Type(), o.Type())
	s += fmt.Sprintf("length %d (%d)", (o.Len() * 8), o.Len())
	s += fmt.Sprintf(": %s/%d, ", o.Prefix, o.PrefixLength)
	f := []string{}
	if o.OnLink {
		f = append(f, "onlink")
	}
	if o.Auto {
		f = append(f, "auto")
	}
	s += fmt.Sprintf("Flags %s, ", f)
	s += fmt.Sprintf("valid time %ds, ", o.ValidLifetime)
	s += fmt.Sprintf("pref. time %ds", o.PreferredLifetime)

	return s
}

// Len implements the Len method of ICMPOption interface.
func (o *ICMPOptionPrefixInformation) Len() uint8 {
	if o == nil {
		return 0
	}

	// Prefix information options are always 4
	return 4
}

// Marshal implements the Marshal method of ICMPOption interface.
func (o *ICMPOptionPrefixInformation) Marshal() ([]byte, error) {
	b := make([]byte, 16)
	// option header
	b[0] = byte(o.Type())
	b[1] = byte(o.Len())
	// option fields
	b[2] = byte(o.PrefixLength)
	if o.OnLink {
		b[3] ^= 0x80
	}
	if o.Auto {
		b[3] ^= 0x40
	}
	binary.BigEndian.PutUint32(b[4:8], uint32(o.ValidLifetime))
	binary.BigEndian.PutUint32(b[8:12], uint32(o.PreferredLifetime))
	b = append(b, o.Prefix...)

	return b, nil
}

// As defined in https://tools.ietf.org/html/rfc4861#section-4.6.4
type ICMPOptionMTU struct {
	*ICMPOptionBase
	MTU uint32
}

// String implements the String method of ICMPOption interface.
func (o *ICMPOptionMTU) String() string {
	s := fmt.Sprintf("%s option (%d), ", o.Type(), o.Type())
	s += fmt.Sprintf("length %d (%d)", (o.Len() * 8), o.Len())
	s += fmt.Sprintf(": %d", o.MTU)

	return s
}

// Len implements the Len method of ICMPOption interface.
func (o *ICMPOptionMTU) Len() uint8 {
	if o == nil {
		return 0
	}

	// MTU options are always 1
	return 1
}

// Marshal implements the Marshal method of ICMPOption interface.
func (o *ICMPOptionMTU) Marshal() ([]byte, error) {
	// option header
	b := make([]byte, 8)
	b[0] = byte(o.Type())
	b[1] = byte(o.Len())
	// option fields
	binary.BigEndian.PutUint32(b[4:8], uint32(o.MTU))

	return b, nil
}

// As defined in https://tools.ietf.org/html/rfc3971#section-5.3.2
type ICMPOptionNonce struct {
	*ICMPOptionBase
	Nonce uint64
}

// String implements the String method of ICMPOption interface.
func (o *ICMPOptionNonce) String() string {
	s := fmt.Sprintf("%s option (%d), ", o.Type(), o.Type())
	s += fmt.Sprintf("length %d (%d)", (o.Len() * 8), o.Len())
	s += fmt.Sprintf(": %d", o.Nonce)

	return s
}

// Len implements the Len method of ICMPOption interface.
func (o *ICMPOptionNonce) Len() uint8 {
	if o == nil {
		return 0
	}

	// TODO: return proper length
	return 1
}

// Marshal implements the Marshal method of ICMPOption interface.
func (o *ICMPOptionNonce) Marshal() ([]byte, error) {
	// NOTE: theoretically, larger nonces are possible
	// as long as it adds multiples of 8 bytes to the max of
	// 6 bytes set below.
	if o.Nonce > 281474976710655 {
		return nil, fmt.Errorf("nonce %d too large to fit in boundaries", o.Nonce)
	}

	// option header
	b := make([]byte, 2)
	b[0] = byte(o.Type())
	b[1] = byte(o.Len())
	// option fields

	// add last 6 bytes of nonce
	n := make([]byte, 8)
	binary.BigEndian.PutUint64(n, o.Nonce)
	b = append(b, n[2:8]...)

	return b, nil
}

// As defined in https://tools.ietf.org/html/rfc6106#section-5.1
type ICMPOptionRecursiveDNSServer struct {
	*ICMPOptionBase
	Lifetime uint32
	Servers  []net.IP
}

// Len implements the Len method of ICMPOption interface.
func (o *ICMPOptionRecursiveDNSServer) Len() uint8 {
	if o == nil {
		return 0
	}

	return 1 + uint8(len(o.Servers)*2)
}

// String implements the String method of ICMPOption interface.
func (o *ICMPOptionRecursiveDNSServer) String() string {
	s := fmt.Sprintf("%s option (%d), ", o.Type(), o.Type())
	s += fmt.Sprintf("length %d (%d): ", (o.Len() * 8), o.Len())
	s += fmt.Sprintf("lifetime %ds, ", o.Lifetime)
	for _, a := range o.Servers {
		s += fmt.Sprintf("addr: %s ", a.String())
	}

	return strings.TrimSuffix(s, " ")
}

// Marshal implements the Marshal method of ICMPOption interface.
func (o *ICMPOptionRecursiveDNSServer) Marshal() ([]byte, error) {
	b := make([]byte, 8)
	// option header
	b[0] = byte(o.Type())
	b[1] = byte(o.Len())
	// option fields
	binary.BigEndian.PutUint32(b[4:8], uint32(o.Lifetime))
	for _, s := range o.Servers {
		b = append(b, s...)
	}

	return b, nil
}

// As defined in https://tools.ietf.org/html/rfc6106#section-5.2
type ICMPOptionDNSSearchList struct {
	*ICMPOptionBase
	Lifetime    uint32
	DomainNames []string
}

// String implements the String method of ICMPOption interface.
func (o *ICMPOptionDNSSearchList) String() string {
	s := fmt.Sprintf("%s option (%d), ", o.Type(), o.Type())
	s += fmt.Sprintf("length %d (%d): ", (o.Len() * 8), o.Len())
	s += fmt.Sprintf("lifetime %ds, ", o.Lifetime)
	s += fmt.Sprintf("domain(s) %s", strings.Join(o.DomainNames, ", "))
	return s
}

// Len implements the Len method of ICMPOption interface.
func (o *ICMPOptionDNSSearchList) Len() uint8 {
	if o == nil {
		return 0
	}

	return 2 + uint8(len(o.DomainNames)*2)
}

// Marshal implements the Marshal method of ICMPOption interface.
func (o *ICMPOptionDNSSearchList) Marshal() ([]byte, error) {
	b := make([]byte, 8)
	// option header
	b[0] = byte(o.Type())
	b[1] = byte(o.Len())
	// option fields
	binary.BigEndian.PutUint32(b[4:8], uint32(o.Lifetime))
	b = append(b, encDomainName(o.DomainNames)...)

	return b, nil
}

func parseOptions(b []byte) ([]ICMPOption, error) {
	// empty container
	var icmpOptions = []ICMPOption{}

	for {
		// left over bytes are less than minimum option length
		if len(b) < 8 {
			break
		}

		// beginning of header specifies type and length
		optionType := ICMPOptionType(b[0])
		optionLength := uint8(b[1])
		// check if we got enought data for at least as long as optionLength specifies
		if uint8(len(b)) < (optionLength * 8) {
			return nil, fmt.Errorf("too few bytes received: %d while at least %d expected", len(b), (optionLength * 8))
		}

		var currentOption ICMPOption

		switch optionType {
		case ICMPOptionTypeSourceLinkLayerAddress:
			if optionLength != 1 {
				return nil, fmt.Errorf("option %s (%d) too short: %d should be 1", optionType, optionType, optionLength)
			}

			currentOption = &ICMPOptionSourceLinkLayerAddress{
				ICMPOptionBase: &ICMPOptionBase{
					optionType: optionType,
				},
				LinkLayerAddress: b[2:8],
			}

		case ICMPOptionTypeTargetLinkLayerAddress:
			if optionLength != 1 {
				return nil, fmt.Errorf("option %s (%d) too short: %d should be 1", optionType, optionType, optionLength)
			}

			currentOption = &ICMPOptionTargetLinkLayerAddress{
				ICMPOptionBase: &ICMPOptionBase{
					optionType: optionType,
				},
				LinkLayerAddress: b[2:8],
			}

		case ICMPOptionTypePrefixInformation:
			if optionLength != 4 {
				return nil, fmt.Errorf("option %s (%d) too short: %d should be 4", optionType, optionType, optionLength)
			}

			currentOption = &ICMPOptionPrefixInformation{
				ICMPOptionBase: &ICMPOptionBase{
					optionType: optionType,
				},
				PrefixLength:      uint8(b[2]),
				OnLink:            (b[3]&0x80 > 0),
				Auto:              (b[3]&0x40 > 0),
				ValidLifetime:     binary.BigEndian.Uint32(b[4:8]),
				PreferredLifetime: binary.BigEndian.Uint32(b[8:12]),
				Prefix:            net.IP(b[16:32]),
			}

		case ICMPOptionTypeMTU:
			if optionLength != 1 {
				return nil, fmt.Errorf("option %s (%d) too short: %d should be 1", optionType, optionType, optionLength)
			}

			currentOption = &ICMPOptionMTU{
				ICMPOptionBase: &ICMPOptionBase{
					optionType: optionType,
				},
				MTU: binary.BigEndian.Uint32(b[4:8]),
			}

		case ICMPOptionTypeNonce:
			if optionLength != 1 {
				return nil, fmt.Errorf("option %s (%d) too short: %d should be 1", optionType, optionType, optionLength)
			}

			currentOption = &ICMPOptionNonce{
				ICMPOptionBase: &ICMPOptionBase{
					optionType: optionType,
				},
			}

			n := make([]byte, 2)
			n = append(n, b[2:8]...)
			currentOption.(*ICMPOptionNonce).Nonce = binary.BigEndian.Uint64(n)

		case ICMPOptionTypeRecursiveDNSServer:
			if optionLength < 3 {
				return nil, fmt.Errorf("option %s (%d) too short: %d should at least be 3", optionType, optionType, optionLength)
			}

			currentOption = &ICMPOptionRecursiveDNSServer{
				ICMPOptionBase: &ICMPOptionBase{
					optionType: optionType,
				},
				Lifetime: binary.BigEndian.Uint32(b[4:8]),
			}

			var servers []net.IP
			for i := 8; i < (int(optionLength) * 8); i += 16 {
				servers = append(servers, net.IP(b[i:(i+16)]))
			}

			currentOption.(*ICMPOptionRecursiveDNSServer).Servers = servers

		case ICMPOptionTypeDNSSearchList:
			if optionLength < 4 {
				return nil, fmt.Errorf("option %s (%d) too short: %d should at least be 4", optionType, optionType, optionLength)
			}

			currentOption = &ICMPOptionDNSSearchList{
				ICMPOptionBase: &ICMPOptionBase{
					optionType: optionType,
				},
				Lifetime: binary.BigEndian.Uint32(b[4:8]),
			}

			currentOption.(*ICMPOptionDNSSearchList).DomainNames = decDomainName(b[8:(optionLength * 8)])

		default:
			currentOption = &ICMPOptionUnknown{
				optionLength: optionLength,
				optionType:   optionType,
				body:         b[2:(optionLength * 8)],
			}
		}

		if optionLength != currentOption.Len() {
			return nil, fmt.Errorf("length mismatch while parsing %s: %d should be %d", optionType, currentOption.Len(), optionLength)
		}

		// add new option to array of options
		icmpOptions = append(icmpOptions, currentOption)

		// are we at the end of the byte slice
		if len(b) <= int(optionLength*8) {
			break
		}

		// chop off bytes for this option
		b = b[(optionLength * 8):]
	}

	return icmpOptions, nil
}
