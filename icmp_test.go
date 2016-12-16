package ndp

import (
	"bytes"
	"net"
	"testing"

	"golang.org/x/net/ipv6"
)

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
