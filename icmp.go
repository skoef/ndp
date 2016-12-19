package ndp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/ipv6"
)

var (
	errMessageTooShort = errors.New("message too short")
)

type ICMP interface {
	String() string
	Marshal() ([]byte, error)
	Type() ipv6.ICMPType
	optMarshal() ([]byte, error)
}

type ICMPBase struct {
	icmpType ipv6.ICMPType
	length   uint8
	Options  []ICMPOption
}

func (p *ICMPBase) Type() ipv6.ICMPType {
	return p.icmpType
}

func (p *ICMPBase) optMarshal() ([]byte, error) {
	var b []byte
	for _, o := range p.Options {
		m, err := o.Marshal()
		if err != nil {
			return nil, err
		}

		b = append(b, m...)
	}

	return b, nil
}

func ParseMessage(b []byte) (ICMP, error) {
	if len(b) < 4 {
		return nil, errMessageTooShort
	}

	icmpType := ipv6.ICMPType(b[0])
	var message ICMP

	switch icmpType {
	case ipv6.ICMPTypeRouterSolicitation:
		message = &ICMPRouterSolicitation{
			ICMPBase: &ICMPBase{
				icmpType: icmpType,
			},
		}

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
			ICMPBase: &ICMPBase{
				icmpType: icmpType,
			},
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
			ICMPBase: &ICMPBase{
				icmpType: icmpType,
			},
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
			ICMPBase: &ICMPBase{
				icmpType: icmpType,
			},
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

// As defined in https://tools.ietf.org/html/rfc4861#section-4.1
type ICMPRouterSolicitation struct {
	*ICMPBase
}

func (p *ICMPRouterSolicitation) String() string {
	m, _ := p.Marshal()
	s := fmt.Sprintf("%s, length %d\n", p.Type(), uint8(len(m)))
	for _, o := range p.Options {
		s += fmt.Sprintf("    %s\n", o)
	}

	return strings.TrimSuffix(s, "\n")
}

func (p *ICMPRouterSolicitation) Marshal() ([]byte, error) {
	b := make([]byte, 8)
	// message header
	b[0] = uint8(p.Type())
	// b[1] = code, always 0
	// b[2:3] = checksum, TODO
	// add options
	om, err := p.optMarshal()
	if err != nil {
		return nil, err
	}

	b = append(b, om...)
	return b, nil
}

// As defined in https://tools.ietf.org/html/rfc4861#section-4.2
type ICMPRouterAdvertisement struct {
	*ICMPBase
	HopLimit       uint8
	ManagedAddress bool
	OtherStateful  bool
	HomeAgent      bool
	RouterLifeTime uint16
	ReachableTime  uint32
	RetransTimer   uint32
}

func (p *ICMPRouterAdvertisement) String() string {
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
	s += fmt.Sprintf("router lifetime %ds, ", p.RouterLifeTime)
	s += fmt.Sprintf("reachable time %ds, ", p.ReachableTime)
	s += fmt.Sprintf("retrans time %ds\n", p.RetransTimer)
	for _, o := range p.Options {
		s += fmt.Sprintf("    %s\n", o)
	}

	return strings.TrimSuffix(s, "\n")
}

func (p *ICMPRouterAdvertisement) Marshal() ([]byte, error) {
	b := make([]byte, 16)
	// message header
	b[0] = uint8(p.Type())
	// b[1] = code, always 0
	// b[2:3] = checksum, TODO
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
	binary.BigEndian.PutUint16(b[6:8], uint16(p.RouterLifeTime))
	binary.BigEndian.PutUint32(b[8:12], uint32(p.ReachableTime))
	binary.BigEndian.PutUint32(b[12:16], uint32(p.RetransTimer))
	// add options
	om, err := p.optMarshal()
	if err != nil {
		return nil, err
	}

	b = append(b, om...)
	return b, nil
}

// As defined in https://tools.ietf.org/html/rfc4861#section-4.3
type ICMPNeighborSolicitation struct {
	*ICMPBase
	TargetAddress net.IP
}

func (p *ICMPNeighborSolicitation) String() string {
	m, _ := p.Marshal()
	s := fmt.Sprintf("%s, length %d, ", p.Type(), uint8(len(m)))
	s += fmt.Sprintf("who has %s\n", p.TargetAddress)
	for _, o := range p.Options {
		s += fmt.Sprintf("    %s\n", o)
	}

	return strings.TrimSuffix(s, "\n")
}

func (p *ICMPNeighborSolicitation) Marshal() ([]byte, error) {
	b := make([]byte, 8)
	// message header
	b[0] = uint8(p.Type())
	// b[1] = code, always 0
	// b[2:3] = checksum, TODO
	b = append(b, p.TargetAddress...)
	// add options
	om, err := p.optMarshal()
	if err != nil {
		return nil, err
	}

	b = append(b, om...)
	return b, nil
}

// As defined in https://tools.ietf.org/html/rfc4861#section-4.4
type ICMPNeighborAdvertisement struct {
	*ICMPBase
	Router        bool
	Solicited     bool
	Override      bool
	TargetAddress net.IP
}

func (p *ICMPNeighborAdvertisement) String() string {
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

func (p *ICMPNeighborAdvertisement) Marshal() ([]byte, error) {
	b := make([]byte, 8)
	// message header
	b[0] = uint8(p.Type())
	// b[1] = code, always 0
	// b[2:3] = checksum, TODO
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
	om, err := p.optMarshal()
	if err != nil {
		return nil, err
	}

	b = append(b, om...)

	return b, nil
}
