package ndp

import (
	"encoding/binary"
	"errors"

	"golang.org/x/net/ipv6"
)

var (
	errMessageTooShort = errors.New("message too short")
)

type ICMP interface {
	Len() uint8
	Marshal() ([]byte, error)
}

type ICMPBase struct {
	icmpType ipv6.ICMPType
	length   uint8
	Options  []ICMPOption
}

func (p *ICMPBase) Type() ipv6.ICMPType {
	return p.icmpType
}

func (p *ICMPBase) Len() uint8 {
	return p.length
}

func (p *ICMPBase) Marshal() ([]byte, error) {
	b := make([]byte, p.Len())
	_ = b
	return nil, errors.New("TODO fix me")
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
		return nil, nil
	}
}
