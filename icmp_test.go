package ndp

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/ipv6"
)

func TestICMPNeighborAdvertisement(t *testing.T) {
	icmp := NewICMP(ipv6.ICMPTypeNeighborAdvertisement).(*ICMPNeighborAdvertisement)
	icmp.Router = true
	icmp.Solicited = true
	icmp.Override = true
	icmp.TargetAddress = net.ParseIP("fe80::1")

	if icmp.Type() != ipv6.ICMPTypeNeighborAdvertisement {
		t.Errorf("wrong type: %d instead of %d", icmp.Type(), ipv6.ICMPTypeNeighborAdvertisement)
	}

	marshal, err := icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture := []byte{136, 0, 0, 0, 224, 0, 0, 0, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	descfix := "neighbor advertisement, length 24, tgt is fe80::1, Flags [router solicited override]"
	desc := icmp.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	parsed_icmp, err := ParseMessage(fixture)
	if err != nil {
		t.Error(err)
	}

	parsed_marshal, err := parsed_icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsed_marshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsed_marshal)
	}

	// add option
	option := NewICMPOption(ICMPOptionTypeTargetLinkLayerAddress).(*ICMPOptionTargetLinkLayerAddress)
	option.LinkLayerAddress, err = net.ParseMAC("a1:b2:c3:d4:e5:f6")
	if err != nil {
		t.Error(err)
	}

	icmp.AddOption(option)

	marshal, err = icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture = []byte{136, 0, 0, 0, 224, 0, 0, 0, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 161, 178, 195, 212, 229, 246}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	parsed_icmp, err = ParseMessage(fixture)
	if err != nil {
		t.Error(err)
	}

	parsed_marshal, err = parsed_icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsed_marshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsed_marshal)
	}
}

func TestICMPNeighborSolicitation(t *testing.T) {
	icmp := NewICMP(ipv6.ICMPTypeNeighborSolicitation).(*ICMPNeighborSolicitation)
	icmp.TargetAddress = net.ParseIP("fe80::1")

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

	parsed_icmp, err := ParseMessage(fixture)
	if err != nil {
		t.Error(err)
	}

	parsed_marshal, err := parsed_icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsed_marshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsed_marshal)
	}

	// add option
	option := NewICMPOption(ICMPOptionTypeSourceLinkLayerAddress).(*ICMPOptionSourceLinkLayerAddress)
	option.LinkLayerAddress, err = net.ParseMAC("a1:b2:c3:d4:e5:f6")
	if err != nil {
		t.Error(err)
	}

	icmp.AddOption(option)

	marshal, err = icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture = []byte{135, 0, 0, 0, 0, 0, 0, 0, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 161, 178, 195, 212, 229, 246}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	parsed_icmp, err = ParseMessage(fixture)
	if err != nil {
		t.Error(err)
	}

	parsed_marshal, err = parsed_icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsed_marshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsed_marshal)
	}
}

func TestICMPRouterSolicitation(t *testing.T) {
	icmp := NewICMP(ipv6.ICMPTypeRouterSolicitation).(*ICMPRouterSolicitation)

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

	parsed_icmp, err := ParseMessage(fixture)
	if err != nil {
		t.Error(err)
	}

	parsed_marshal, err := parsed_icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsed_marshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsed_marshal)
	}

	// add option
	option := NewICMPOption(ICMPOptionTypeSourceLinkLayerAddress).(*ICMPOptionSourceLinkLayerAddress)
	option.LinkLayerAddress, err = net.ParseMAC("a1:b2:c3:d4:e5:f6")
	if err != nil {
		t.Error(err)
	}

	icmp.AddOption(option)

	marshal, err = icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture = []byte{133, 0, 0, 0, 0, 0, 0, 0, 1, 1, 161, 178, 195, 212, 229, 246}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	parsed_icmp, err = ParseMessage(fixture)
	if err != nil {
		t.Error(err)
	}

	parsed_marshal, err = parsed_icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsed_marshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsed_marshal)
	}
}

func TestICMPRouterAdvertisement(t *testing.T) {
	icmp := NewICMP(ipv6.ICMPTypeRouterAdvertisement).(*ICMPRouterAdvertisement)
	icmp.HopLimit = 64
	icmp.ManagedAddress = true
	icmp.OtherStateful = true
	icmp.HomeAgent = true
	icmp.RouterLifeTime = 3600
	icmp.ReachableTime = 7200
	icmp.RetransTimer = 1800
	icmp.RouterPreference = RouterPreferenceHigh

	if icmp.Type() != ipv6.ICMPTypeRouterAdvertisement {
		t.Errorf("wrong type: %d instead of %d", icmp.Type(), ipv6.ICMPTypeRouterAdvertisement)
	}

	marshal, err := icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture := []byte{134, 0, 0, 0, 64, 232, 14, 16, 0, 0, 28, 32, 0, 0, 7, 8}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	descfix := "router advertisement, length 16\n hop limit 64, Flags [managed other stateful home agent], router lifetime 3600s, reachable time 7200s, retrans time 1800s"
	desc := icmp.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	parsed_icmp, err := ParseMessage(fixture)
	if err != nil {
		t.Error(err)
	}

	parsed_marshal, err := parsed_icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsed_marshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsed_marshal)
	}

	// add RDNSS option
	dnss_option := NewICMPOption(ICMPOptionTypeRecursiveDNSServer).(*ICMPOptionRecursiveDNSServer)
	dnss_option.Lifetime = 300
	dnss_option.Servers = []net.IP{net.ParseIP("2001:4860:4860::8844"), net.ParseIP("2001:4860:4860::8888")}

	icmp.AddOption(dnss_option)

	marshal, err = icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture = []byte{134, 0, 0, 0, 64, 232, 14, 16, 0, 0, 28, 32, 0, 0, 7, 8, 25, 5, 0, 0, 0, 0, 1, 44, 32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 68, 32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 136}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	parsed_icmp, err = ParseMessage(fixture)
	if err != nil {
		t.Error(err)
	}

	parsed_marshal, err = parsed_icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsed_marshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsed_marshal)
	}

	// add DNSSL option
	dnssl_option := NewICMPOption(ICMPOptionTypeDNSSearchList).(*ICMPOptionDNSSearchList)
	dnssl_option.Lifetime = 10
	dnssl_option.DomainNames = []string{"basement.golang.org."}

	icmp.AddOption(dnssl_option)

	marshal, err = icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture = []byte{134, 0, 0, 0, 64, 232, 14, 16, 0, 0, 28, 32, 0, 0, 7, 8, 25, 5, 0, 0, 0, 0, 1, 44, 32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 68, 32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 136, 31, 4, 0, 0, 0, 0, 0, 10, 8, 98, 97, 115, 101, 109, 101, 110, 116, 6, 103, 111, 108, 97, 110, 103, 3, 111, 114, 103, 0, 0, 0, 0}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	// add MTU option
	mtu_option := NewICMPOption(ICMPOptionTypeMTU).(*ICMPOptionMTU)
	mtu_option.MTU = 1500
	icmp.AddOption(mtu_option)

	marshal, err = icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture = []byte{134, 0, 0, 0, 64, 232, 14, 16, 0, 0, 28, 32, 0, 0, 7, 8, 25, 5, 0, 0, 0, 0, 1, 44, 32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 68, 32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 136, 31, 4, 0, 0, 0, 0, 0, 10, 8, 98, 97, 115, 101, 109, 101, 110, 116, 6, 103, 111, 108, 97, 110, 103, 3, 111, 114, 103, 0, 0, 0, 0, 5, 1, 0, 0, 0, 0, 5, 220}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	parsed_icmp, err = ParseMessage(fixture)
	if err != nil {
		t.Error(err)
	}

	parsed_marshal, err = parsed_icmp.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsed_marshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsed_marshal)
	}
}
