package ndp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

var (
	errMessageTooShort = errors.New("message too short")
)

// ICMP implements an interface to base various ICMPv6 packets on
type ICMP interface {
	String() string
	Marshal() ([]byte, error)
	Type() ipv6.ICMPType
}

type optionContainer struct {
	Options ICMPOptions
}

// Checksum calculates and sets checksum to a given body of bytes
// based on source and destination IP
func Checksum(body *[]byte, srcIP, dstIP net.IP) error {
	// from golang.org/x/net/icmp/message.go
	checksum := func(b []byte) uint16 {
		csumcv := len(b) - 1 // checksum coverage
		s := uint32(0)
		for i := 0; i < csumcv; i += 2 {
			s += uint32(b[i+1])<<8 | uint32(b[i])
		}
		if csumcv&1 == 0 {
			s += uint32(b[csumcv])
		}
		s = s>>16 + s&0xffff
		s = s + s>>16
		return ^uint16(s)
	}

	b := *body

	// remember origin length
	l := len(b)
	// generate pseudo header
	psh := icmp.IPv6PseudoHeader(srcIP, dstIP)
	// concat psh with b
	b = append(psh, b...)
	// set length of total packet
	off := 2 * net.IPv6len
	binary.BigEndian.PutUint32(b[off:off+4], uint32(l))
	// calculate checksum
	s := checksum(b)
	// set checksum in bytes and return original Body
	b[len(psh)+2] ^= byte(s)
	b[len(psh)+3] ^= byte(s >> 8)

	*body = b[len(psh):]
	return nil
}

// AddOption adds given ICMPOption to options of ICMP
func (oc *optionContainer) AddOption(o ICMPOption) {
	oc.Options = append(oc.Options, o)
}

// HasOption returns true if ICMP contains option of type ICMPOptionType
func (oc optionContainer) HasOption(t ICMPOptionType) bool {
	for _, o := range oc.Options {
		if o.Type() == t {
			return true
		}
	}
	return false
}

// GetOption returns ICMPOption of type ICMPOptionType or error if ICMP has
// no such option
func (oc optionContainer) GetOption(t ICMPOptionType) (*ICMPOption, error) {
	for _, o := range oc.Options {
		if o.Type() == t {
			return &o, nil
		}
	}

	return nil, fmt.Errorf("option %d not found", t)
}

// ParseMessage returns ICMP and its ICMPOptions for given bytes or error
// if it couldn't parse it
func ParseMessage(b []byte) (ICMP, error) {
	if len(b) < 4 {
		return nil, errMessageTooShort
	}

	icmpType := ipv6.ICMPType(b[0])
	var message ICMP

	switch icmpType {
	case ipv6.ICMPTypeRouterSolicitation:
		message = &ICMPRouterSolicitation{}

		if len(b) > 8 {
			options, err := parseOptions(b[8:])
			if err != nil {
				return nil, err
			}

			message.(*ICMPRouterSolicitation).Options = options
		}

		return message, nil

	case ipv6.ICMPTypeRouterAdvertisement:
		message = &ICMPRouterAdvertisement{
			HopLimit:       uint8(b[4]),
			ManagedAddress: false,
			OtherStateful:  false,
			HomeAgent:      false,
			RouterLifeTime: binary.BigEndian.Uint16(b[6:8]),
			ReachableTime:  binary.BigEndian.Uint32(b[8:12]),
			RetransTimer:   binary.BigEndian.Uint32(b[12:16]),
		}

		// parse flags
		if b[5]&0x80 > 0 {
			message.(*ICMPRouterAdvertisement).ManagedAddress = true
		}
		if b[5]&0x40 > 0 {
			message.(*ICMPRouterAdvertisement).OtherStateful = true
		}
		if b[5]&0x20 > 0 {
			message.(*ICMPRouterAdvertisement).HomeAgent = true
		}
		if b[5]&0x10 > 0 && b[5]&0x8 > 0 {
			message.(*ICMPRouterAdvertisement).RouterPreference = RouterPreferenceLow
		} else if b[5]&0x08 > 0 {
			message.(*ICMPRouterAdvertisement).RouterPreference = RouterPreferenceHigh
		}

		if len(b) > 16 {
			options, err := parseOptions(b[16:])
			if err != nil {
				return nil, err
			}

			message.(*ICMPRouterAdvertisement).Options = options
		}

		return message, nil

	case ipv6.ICMPTypeNeighborSolicitation:
		message = &ICMPNeighborSolicitation{
			TargetAddress: b[8:24],
		}

		if len(b) > 24 {
			options, err := parseOptions(b[24:])
			if err != nil {
				return nil, err
			}

			message.(*ICMPNeighborSolicitation).Options = options
		}

		return message, nil

	case ipv6.ICMPTypeNeighborAdvertisement:
		message = &ICMPNeighborAdvertisement{
			TargetAddress: b[8:24],
		}

		// parse flags
		if b[4]&0x80 > 0 {
			message.(*ICMPNeighborAdvertisement).Router = true
		}
		if b[4]&0x40 > 0 {
			message.(*ICMPNeighborAdvertisement).Solicited = true
		}
		if b[4]&0x20 > 0 {
			message.(*ICMPNeighborAdvertisement).Override = true
		}

		if len(b) > 24 {
			options, err := parseOptions(b[24:])
			if err != nil {
				return nil, err
			}

			message.(*ICMPNeighborAdvertisement).Options = options
		}

		return message, nil

	default:
		return nil, fmt.Errorf("message with type %d not supported", icmpType)
	}
}

// ICMPRouterSolicitation implements the Router Solicitation message as
// described at https://tools.ietf.org/html/rfc4861#section-4.1
type ICMPRouterSolicitation struct {
	optionContainer
}

func (p ICMPRouterSolicitation) String() string {
	m, _ := p.Marshal()
	s := fmt.Sprintf("%s, length %d\n", p.Type(), uint8(len(m)))
	for _, o := range p.Options {
		s += fmt.Sprintf("    %s\n", o)
	}

	return strings.TrimSuffix(s, "\n")
}

// Type returns ipv6.ICMPTypeRouterSolicitation
func (p ICMPRouterSolicitation) Type() ipv6.ICMPType {
	return ipv6.ICMPTypeRouterSolicitation
}

// Marshal returns byte slice representing this ICMPRouterSolicitation
func (p ICMPRouterSolicitation) Marshal() ([]byte, error) {
	b := make([]byte, 8)
	// message header
	b[0] = uint8(p.Type())
	// b[1] = code, always 0
	// b[2:3] = checksum, calculated separately
	// add options
	om, err := p.Options.Marshal()
	if err != nil {
		return nil, err
	}

	b = append(b, om...)
	return b, nil
}

// RouterPreferenceField implements the Router Preference Values as
// described at https://tools.ietf.org/html/rfc4191#section-2.1
type RouterPreferenceField int

// types currently defined
const (
	RouterPreferenceMedium RouterPreferenceField = iota
	RouterPreferenceHigh
	_
	RouterPreferenceLow
)

func (typ RouterPreferenceField) String() string {
	switch typ {
	case RouterPreferenceLow:
		return "low"
	case RouterPreferenceMedium:
		return "medium"
	case RouterPreferenceHigh:
		return "high"
	default:
		return "<nil>"
	}
}

// ICMPRouterAdvertisement implements the Router Advertisement message as
// described at https://tools.ietf.org/html/rfc4861#section-4.2
type ICMPRouterAdvertisement struct {
	optionContainer
	HopLimit         uint8
	ManagedAddress   bool
	OtherStateful    bool
	HomeAgent        bool
	RouterPreference RouterPreferenceField
	RouterLifeTime   uint16
	ReachableTime    uint32
	RetransTimer     uint32
}

func (p ICMPRouterAdvertisement) String() string {
	m, _ := p.Marshal()
	s := fmt.Sprintf("%s, length %d\n ", p.Type(), uint8(len(m)))
	s += fmt.Sprintf("hop limit %d, ", p.HopLimit)
	f := []string{}
	if p.ManagedAddress {
		f = append(f, "managed")
	}
	if p.OtherStateful {
		f = append(f, "other stateful")
	}
	if p.HomeAgent {
		f = append(f, "home agent")
	}
	s += fmt.Sprintf("Flags %s, ", f)
	s += fmt.Sprintf("pref %s, ", p.RouterPreference)
	s += fmt.Sprintf("router lifetime %ds, ", p.RouterLifeTime)
	s += fmt.Sprintf("reachable time %ds, ", p.ReachableTime)
	s += fmt.Sprintf("retrans time %ds\n", p.RetransTimer)
	for _, o := range p.Options {
		s += fmt.Sprintf("    %s\n", o)
	}

	return strings.TrimSuffix(s, "\n")
}

// Type returns ipv6.ICMPTypeRouterAdvertisement
func (p ICMPRouterAdvertisement) Type() ipv6.ICMPType {
	return ipv6.ICMPTypeRouterAdvertisement
}

// Marshal returns byte slice representing this ICMPRouterAdvertisement
func (p ICMPRouterAdvertisement) Marshal() ([]byte, error) {
	b := make([]byte, 16)
	// message header
	b[0] = uint8(p.Type())
	// b[1] = code, always 0
	// b[2:3] = checksum, calculated separately
	b[4] ^= byte(p.HopLimit)
	if p.ManagedAddress {
		b[5] ^= 0x80
	}
	if p.OtherStateful {
		b[5] ^= 0x40
	}
	if p.HomeAgent {
		b[5] ^= 0x20
	}
	// medium is 00, which is default
	switch p.RouterPreference {
	case RouterPreferenceLow:
		b[5] ^= 0x18
	case RouterPreferenceHigh:
		b[5] ^= 0x08
	}
	binary.BigEndian.PutUint16(b[6:8], uint16(p.RouterLifeTime))
	binary.BigEndian.PutUint32(b[8:12], uint32(p.ReachableTime))
	binary.BigEndian.PutUint32(b[12:16], uint32(p.RetransTimer))
	// add options
	om, err := p.Options.Marshal()
	if err != nil {
		return nil, err
	}

	b = append(b, om...)
	return b, nil
}

// ICMPNeighborSolicitation implements the Neighbor Solicitation message as
// described at https://tools.ietf.org/html/rfc4861#section-4.3
type ICMPNeighborSolicitation struct {
	optionContainer
	TargetAddress net.IP
}

func (p ICMPNeighborSolicitation) String() string {
	m, _ := p.Marshal()
	s := fmt.Sprintf("%s, length %d, ", p.Type(), uint8(len(m)))
	s += fmt.Sprintf("who has %s\n", p.TargetAddress)
	for _, o := range p.Options {
		s += fmt.Sprintf("    %s\n", o)
	}

	return strings.TrimSuffix(s, "\n")
}

// Type returns ipv6.ICMPTypeNeighborSolicitation
func (p ICMPNeighborSolicitation) Type() ipv6.ICMPType {
	return ipv6.ICMPTypeNeighborSolicitation
}

// Marshal returns byte slice representing this ICMPNeighborSolicitation
func (p ICMPNeighborSolicitation) Marshal() ([]byte, error) {
	b := make([]byte, 8)
	// message header
	b[0] = uint8(p.Type())
	// b[1] = code, always 0
	// b[2:3] = checksum, calculated separately
	b = append(b, p.TargetAddress...)
	// add options
	om, err := p.Options.Marshal()
	if err != nil {
		return nil, err
	}

	b = append(b, om...)
	return b, nil
}

// ICMPNeighborAdvertisement implements the Neighbor Advertisement message as
// described at https://tools.ietf.org/html/rfc4861#section-4.4
type ICMPNeighborAdvertisement struct {
	optionContainer
	Router        bool
	Solicited     bool
	Override      bool
	TargetAddress net.IP
}

func (p ICMPNeighborAdvertisement) String() string {
	m, _ := p.Marshal()
	s := fmt.Sprintf("%s, length %d, ", p.Type(), uint8(len(m)))
	s += fmt.Sprintf("tgt is %s, ", p.TargetAddress)
	s += "Flags ["
	if p.Router {
		s += "router "
	}
	if p.Solicited {
		s += "solicited "
	}
	if p.Override {
		s += "override"
	}
	s += "]\n"
	for _, o := range p.Options {
		s += fmt.Sprintf("    %s\n", o)
	}

	return strings.TrimSuffix(s, "\n")
}

// Type returns ipv6.ICMPTypeNeighborAdvertisement
func (p ICMPNeighborAdvertisement) Type() ipv6.ICMPType {
	return ipv6.ICMPTypeNeighborAdvertisement
}

// Marshal returns byte slice representing this ICMPNeighborAdvertisement
func (p ICMPNeighborAdvertisement) Marshal() ([]byte, error) {
	b := make([]byte, 8)
	// message header
	b[0] = uint8(p.Type())
	// b[1] = code, always 0
	// b[2:3] = checksum, calculated separately
	if p.Router {
		b[4] ^= 0x80
	}
	if p.Solicited {
		b[4] ^= 0x40
	}
	if p.Override {
		b[4] ^= 0x20
	}
	b = append(b, p.TargetAddress...)
	// add options
	om, err := p.Options.Marshal()
	if err != nil {
		return nil, err
	}

	b = append(b, om...)

	return b, nil
}
