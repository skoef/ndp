package ndp

import (
	"bytes"
	"net"
	"testing"

	"golang.org/x/net/ipv6"
)

func TestICMPRouterSolicitation(t *testing.T) {
	icmp := &ICMPRouterSolicitation{
		ICMPBase: &ICMPBase{
			icmpType: ipv6.ICMPTypeRouterSolicitation,
		},
	}

	if icmp.Type() != ipv6.ICMPTypeRouterSolicitation {
		t.Errorf("wrong type: %d instead of %d", icmp.Type(), ipv6.ICMPTypeRouterSolicitation)
	}

	if icmp.Len() != 1 {
		t.Errorf("wrong length, %d != 1", icmp.Len())
	}

	marshal, err := icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture := []byte{133, 0, 0, 0, 0, 0, 0, 0}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	// add option
	option := &ICMPOptionSourceLinkLayerAddress{
		ICMPOptionBase: &ICMPOptionBase{
			optionType: ICMPOptionTypeSourceLinkLayerAddress,
		},
	}

	option.linkLayerAddress, err = net.ParseMAC("a1:b2:c3:d4:e5:f6")
	if err != nil {
		t.Error(err)
	}

	icmp.Options = []ICMPOption{option}

	if icmp.Len() != 2 {
		t.Errorf("wrong length, %d != 2", icmp.Len())
	}

	marshal, err = icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture = []byte{133, 0, 0, 0, 0, 0, 0, 0, 1, 1, 161, 178, 195, 212, 229, 246}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}
}

func TestICMPRouterAdvertismentMarshal(t *testing.T) {
	icmp := &ICMPRouterAdvertisement{
		ICMPBase: &ICMPBase{
			icmpType: ipv6.ICMPTypeRouterAdvertisement,
		},
		HopLimit:       64,
		ManagedAddress: true,
		OtherStateful:  true,
		HomeAgent:      true,
		RouterLifeTime: uint16(3600),
		ReachableTime:  uint32(7200),
		RetransTimer:   uint32(1800),
	}

	if icmp.Type() != ipv6.ICMPTypeRouterAdvertisement {
		t.Errorf("wrong type: %d instead of %d", icmp.Type(), ipv6.ICMPTypeRouterAdvertisement)
	}

	if icmp.Len() != 16 {
		t.Errorf("wrong length, %d != 16", icmp.Len())
	}

	marshal, err := icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture := []byte{134, 0, 0, 0, 64, 224, 14, 16, 0, 0, 28, 32, 0, 0, 7, 8}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	// add option
	icmp.Options = []ICMPOption{&ICMPOptionRecursiveDNSServer{
		ICMPOptionBase: &ICMPOptionBase{
			optionType: ICMPOptionTypeRecursiveDNSServer,
		},
		Lifetime: 300,
		Servers:  []net.IP{net.ParseIP("2001:4860:4860::8844"), net.ParseIP("2001:4860:4860::8888")},
	}}

	if icmp.Len() != 21 {
		t.Errorf("wrong length, %d != 21", icmp.Len())
	}

	marshal, err = icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture = []byte{134, 0, 0, 0, 64, 224, 14, 16, 0, 0, 28, 32, 0, 0, 7, 8, 25, 5, 0, 0, 0, 0, 1, 44, 32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 68, 32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 136}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}
}
