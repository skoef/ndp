package ndp

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/ipv6"
)

func TestICMPNeighborSolicitation(t *testing.T) {
	icmp := &ICMPNeighborSolicitation{
		ICMPBase: &ICMPBase{
			icmpType: ipv6.ICMPTypeNeighborSolicitation,
		},
		TargetAddress: net.ParseIP("fe80::1"),
	}

	if icmp.Type() != ipv6.ICMPTypeNeighborSolicitation {
		t.Errorf("wrong type: %d instead of %d", icmp.Type(), ipv6.ICMPTypeNeighborSolicitation)
	}

	marshal, err := icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture := []byte{135, 0, 0, 0, 0, 0, 0, 0, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	descfix := "neighbor solicitation, length 24, who has fe80::1"
	desc := icmp.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	// add option
	option := &ICMPOptionSourceLinkLayerAddress{
		ICMPOptionBase: &ICMPOptionBase{
			optionType: ICMPOptionTypeSourceLinkLayerAddress,
		},
	}

	option.LinkLayerAddress, err = net.ParseMAC("a1:b2:c3:d4:e5:f6")
	if err != nil {
		t.Error(err)
	}

	icmp.Options = []ICMPOption{option}

	marshal, err = icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture = []byte{135, 0, 0, 0, 0, 0, 0, 0, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 161, 178, 195, 212, 229, 246}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}
}

func TestICMPRouterSolicitation(t *testing.T) {
	icmp := &ICMPRouterSolicitation{
		ICMPBase: &ICMPBase{
			icmpType: ipv6.ICMPTypeRouterSolicitation,
		},
	}

	if icmp.Type() != ipv6.ICMPTypeRouterSolicitation {
		t.Errorf("wrong type: %d instead of %d", icmp.Type(), ipv6.ICMPTypeRouterSolicitation)
	}

	marshal, err := icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture := []byte{133, 0, 0, 0, 0, 0, 0, 0}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	descfix := "router solicitation, length 8"
	desc := icmp.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	// add option
	option := &ICMPOptionSourceLinkLayerAddress{
		ICMPOptionBase: &ICMPOptionBase{
			optionType: ICMPOptionTypeSourceLinkLayerAddress,
		},
	}

	option.LinkLayerAddress, err = net.ParseMAC("a1:b2:c3:d4:e5:f6")
	if err != nil {
		t.Error(err)
	}

	icmp.Options = []ICMPOption{option}

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

	marshal, err := icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture := []byte{134, 0, 0, 0, 64, 224, 14, 16, 0, 0, 28, 32, 0, 0, 7, 8}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	descfix := "router advertisement, length 16\n hop limit 64, Flags [managed other stateful home agent], router lifetime 3600s, reachable time 7200s, retrans time 1800s"
	desc := icmp.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	// add option
	icmp.Options = []ICMPOption{&ICMPOptionRecursiveDNSServer{
		ICMPOptionBase: &ICMPOptionBase{
			optionType: ICMPOptionTypeRecursiveDNSServer,
		},
		Lifetime: 300,
		Servers:  []net.IP{net.ParseIP("2001:4860:4860::8844"), net.ParseIP("2001:4860:4860::8888")},
	}}

	marshal, err = icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture = []byte{134, 0, 0, 0, 64, 224, 14, 16, 0, 0, 28, 32, 0, 0, 7, 8, 25, 5, 0, 0, 0, 0, 1, 44, 32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 68, 32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 136}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}
}

func TestICMPRedirect(t *testing.T) {
	icmp := &ICMPRedirect{
		ICMPBase: &ICMPBase{
			icmpType: ipv6.ICMPTypeRedirect,
		},
		TargetAddress:      net.ParseIP("fe80::1"),
		DestinationAddress: net.ParseIP("fe80::2"),
	}

	if icmp.Type() != ipv6.ICMPTypeRedirect {
		t.Errorf("wrong type: %d instead of %d", icmp.Type(), ipv6.ICMPTypeRedirect)
	}

	marshal, err := icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture := []byte{137, 0, 0, 0, 0, 0, 0, 0, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	descfix := "redirect message, length 40, redirect fe80::1 to fe80::2"
	desc := icmp.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	// add option
	option := &ICMPOptionTargetLinkLayerAddress{
		ICMPOptionBase: &ICMPOptionBase{
			optionType: ICMPOptionTypeTargetLinkLayerAddress,
		},
	}

	option.LinkLayerAddress, err = net.ParseMAC("a1:b2:c3:d4:e5:f6")
	if err != nil {
		t.Error(err)
	}

	icmp.Options = []ICMPOption{option}

	marshal, err = icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture = []byte{137, 0, 0, 0, 0, 0, 0, 0, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 1, 161, 178, 195, 212, 229, 246}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}
}
