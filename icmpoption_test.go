package ndp

import (
	"bytes"
	"net"
	"testing"
)

func TestICMPOptionDNSSearchList(t *testing.T) {
	option := &ICMPOptionDNSSearchList{
		ICMPOptionBase: &ICMPOptionBase{
			optionType: ICMPOptionTypeDNSSearchList,
		},
		Lifetime:    10,
		DomainNames: []string{"basement.golang.org."},
	}

	if option.Type() != ICMPOptionTypeDNSSearchList {
		t.Errorf("wrong type: %d instead of %d", option.Type(), ICMPOptionTypeDNSSearchList)
	}

	if option.Len() < 4 {
		t.Errorf("wrong length, %d < 4", option.Len())
	}

	marshal, err := option.Marshal()
	if err != nil {
		t.Error(err)
	}

	// fixture describes
	// dnssl option (31), length 32 (4):  lifetime 10s, domain(s): basement.golang.org.
	fixture := []byte{31, 4, 0, 0, 0, 0, 0, 10, 8, 98, 97, 115, 101, 109, 101, 110, 116, 6, 103, 111, 108, 97, 110, 103, 3, 111, 114, 103, 0, 0, 0}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}
}

func TestICMPOptionMTU(t *testing.T) {
	option := &ICMPOptionMTU{
		ICMPOptionBase: &ICMPOptionBase{
			optionType: ICMPOptionTypeMTU,
		},
		MTU: 1500,
	}

	if option.Type() != ICMPOptionTypeMTU {
		t.Errorf("wrong type: %d instead of %d", option.Type(), ICMPOptionTypeMTU)
	}

	if option.Len() != 1 {
		t.Errorf("wrong length, %d != 1", option.Len())
	}

	marshal, err := option.Marshal()
	if err != nil {
		t.Error(err)
	}

	// fixture describes
	// mtu option (5), length 8 (1):  1500
	fixture := []byte{5, 1, 0, 0, 0, 0, 5, 220}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}
}

func TestICMPOptionSourceLinkLayerAddress(t *testing.T) {
	var err error
	option := &ICMPOptionSourceLinkLayerAddress{
		ICMPOptionBase: &ICMPOptionBase{
			optionType: ICMPOptionTypeSourceLinkLayerAddress,
		},
	}
	option.LinkLayerAddress, err = net.ParseMAC("a1:b2:c3:d4:e6:f7")
	if err != nil {
		t.Error(err)
	}

	if option.Type() != ICMPOptionTypeSourceLinkLayerAddress {
		t.Errorf("wrong type: %d instead of %d", option.Type(), ICMPOptionTypeSourceLinkLayerAddress)
	}

	if option.Len() != 1 {
		t.Errorf("wrong length, %d != 1", option.Len())
	}

	marshal, err := option.Marshal()
	if err != nil {
		t.Error(err)
	}

	// fixture describes
	// source link-address option (1), length 8 (1): a1:b2:c3:d4:e6:f7
	fixture := []byte{1, 1, 161, 178, 195, 212, 230, 247}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}
}

func TestICMPOptionTargetLinkLayerAddress(t *testing.T) {
	var err error
	option := &ICMPOptionTargetLinkLayerAddress{
		ICMPOptionBase: &ICMPOptionBase{
			optionType: ICMPOptionTypeTargetLinkLayerAddress,
		},
	}
	option.LinkLayerAddress, err = net.ParseMAC("a1:b2:c3:d4:e6:f7")
	if err != nil {
		t.Error(err)
	}

	if option.Type() != ICMPOptionTypeTargetLinkLayerAddress {
		t.Errorf("wrong type: %d instead of %d", option.Type(), ICMPOptionTypeTargetLinkLayerAddress)
	}

	if option.Len() != 1 {
		t.Errorf("wrong length, %d != 1", option.Len())
	}

	marshal, err := option.Marshal()
	if err != nil {
		t.Error(err)
	}

	// fixture describes
	// target link-address option (1), length 8 (1): a1:b2:c3:d4:e6:f7
	fixture := []byte{2, 1, 161, 178, 195, 212, 230, 247}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}
}

func TestICMPOptionPrefixInformation(t *testing.T) {
	option := &ICMPOptionPrefixInformation{
		ICMPOptionBase: &ICMPOptionBase{
			optionType: ICMPOptionTypePrefixInformation,
		},
		PrefixLength:      64,
		OnLink:            true,
		Auto:              true,
		ValidLifetime:     2592000,
		PreferredLifetime: 604800,
		Prefix:            net.ParseIP("2a00:1450:400e:802::"),
	}

	if option.Type() != ICMPOptionTypePrefixInformation {
		t.Errorf("wrong type: %d instead of %d", option.Type(), ICMPOptionTypePrefixInformation)
	}

	if option.Len() != 4 {
		t.Errorf("wrong length, %d != 4", option.Len())
	}

	marshal, err := option.Marshal()
	if err != nil {
		t.Error(err)
	}

	// fixture describes
	// prefix info option (3), length 32 (4): 2a00:1450:400e:802::/64, Flags [onlink, auto], valid time 2592000s, pref. time 604800s
	fixture := []byte{3, 4, 64, 192, 0, 39, 141, 0, 0, 9, 58, 128, 0, 0, 0, 0, 42, 0, 20, 80, 64, 14, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}
}

func TestICMPOptionRecursiveDNSServer(t *testing.T) {
	option := &ICMPOptionRecursiveDNSServer{
		ICMPOptionBase: &ICMPOptionBase{
			optionType: ICMPOptionTypeRecursiveDNSServer,
		},
		Lifetime: 300,
		Servers:  []net.IP{net.ParseIP("2001:4860:4860::8844")},
	}

	if option.Type() != ICMPOptionTypeRecursiveDNSServer {
		t.Errorf("wrong type: %d instead of %d", option.Type(), ICMPOptionTypeRecursiveDNSServer)
	}

	if option.Len() != 3 {
		t.Errorf("wrong length, %d != 3", option.Len())
	}

	marshal, err := option.Marshal()
	if err != nil {
		t.Error(err)
	}

	// fixture describes
	// rdnss option (25), length 40 (5):  lifetime 300s, addr: 2001:4860:4860::8844
	fixture := []byte{25, 3, 0, 0, 0, 0, 1, 44, 32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 68}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	// check with multiple nameserver IPs
	option.Servers = []net.IP{net.ParseIP("2001:4860:4860::8844"), net.ParseIP("2001:4860:4860::8888")}

	if option.Len() != 5 {
		t.Errorf("wrong length, %d != 5", option.Len())
	}

	marshal, err = option.Marshal()
	if err != nil {
		t.Error(err)
	}

	// fixture describes
	// rdnss option (25), length 40 (5):  lifetime 300s, addr: 2001:4860:4860::8844 addr: 2001:4860:4860::8888
	fixture = []byte{25, 5, 0, 0, 0, 0, 1, 44, 32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 68, 32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 136}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}
}
