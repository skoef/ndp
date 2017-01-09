package ndp

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func TestICMPOptionDNSSearchList(t *testing.T) {
	option := NewICMPOption(ICMPOptionTypeDNSSearchList).(*ICMPOptionDNSSearchList)
	option.Lifetime = 10
	option.DomainNames = []string{"basement.golang.org."}

	if option.Type() != ICMPOptionTypeDNSSearchList {
		t.Errorf("wrong type: %d instead of %d", option.Type(), ICMPOptionTypeDNSSearchList)
	}

	if option.Len() != 4 {
		t.Errorf("wrong length, %d != 4", option.Len())
	}

	marshal, err := option.Marshal()
	if err != nil {
		t.Error(err)
	}

	// fixture describes
	// dnssl option (31), length 32 (4):  lifetime 10s, domain(s): basement.golang.org.
	fixture := []byte{31, 4, 0, 0, 0, 0, 0, 10, 8, 98, 97, 115, 101, 109, 101, 110, 116, 6, 103, 111, 108, 97, 110, 103, 3, 111, 114, 103, 0, 0, 0, 0}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	descfix := "dnssl option (31), length 32 (4): lifetime 10s, domain(s) basement.golang.org."
	desc := option.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	var options []ICMPOption
	options, err = parseOptions(fixture)
	if err != nil {
		t.Error(err)
	}

	if len(options) != 1 {
		t.Errorf("parsed %d options instead of 1", len(options))
	}

	parsed := options[0].(*ICMPOptionDNSSearchList)
	parsedMarshal, err := parsed.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsedMarshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsedMarshal)
	}

	// check with multiple domain names
	option.DomainNames = []string{"basement.golang.org.", "golang.org."}
	if option.Len() != 6 {
		t.Errorf("wrong length, %d != 6", option.Len())
	}

	marshal, err = option.Marshal()
	if err != nil {
		t.Error(err)
	}

	fixture = []byte{31, 6, 0, 0, 0, 0, 0, 10, 8, 98, 97, 115, 101, 109, 101, 110, 116, 6, 103, 111, 108, 97, 110, 103, 3, 111, 114, 103, 0, 6, 103, 111, 108, 97, 110, 103, 3, 111, 114, 103, 0, 0, 0, 0, 0, 0, 0, 0}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of \n%v (%d) did not match \n%v (%d)", fixture, len(fixture), marshal, len(marshal))
	}

	descfix = "dnssl option (31), length 48 (6): lifetime 10s, domain(s) basement.golang.org., golang.org."
	desc = option.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	options, err = parseOptions(fixture)
	if err != nil {
		t.Error(err)
	}

	if len(options) != 1 {
		t.Errorf("parsed %d options instead of 1", len(options))
	}

	parsed = options[0].(*ICMPOptionDNSSearchList)
	parsedMarshal, err = parsed.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsedMarshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsedMarshal)
	}
}

func TestICMPOptionMTU(t *testing.T) {
	option := NewICMPOption(ICMPOptionTypeMTU).(*ICMPOptionMTU)
	option.MTU = 1500

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

	descfix := "mtu option (5), length 8 (1): 1500"
	desc := option.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	var options []ICMPOption
	options, err = parseOptions(fixture)
	if err != nil {
		t.Error(err)
	}

	if len(options) != 1 {
		t.Errorf("parsed %d options instead of 1", len(options))
	}

	parsed := options[0].(*ICMPOptionMTU)
	parsedMarshal, err := parsed.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsedMarshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsedMarshal)
	}
}

func TestICMPOptionNonce(t *testing.T) {
	option := NewICMPOption(ICMPOptionTypeNonce).(*ICMPOptionNonce)
	option.Nonce = 65766764768057

	if option.Type() != ICMPOptionTypeNonce {
		t.Errorf("wrong type: %d instead of %d", option.Type(), ICMPOptionTypeNonce)
	}

	if option.Len() != 1 {
		t.Errorf("wrong length, %d != 1", option.Len())
	}

	marshal, err := option.Marshal()
	if err != nil {
		t.Error(err)
	}

	// fixture describes
	// nonce option (14), length 8 (1): 65766764768057
	fixture := []byte{14, 1, 59, 208, 132, 166, 235, 57}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	descfix := "nonce option (14), length 8 (1): 65766764768057"
	desc := option.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	var options []ICMPOption
	options, err = parseOptions(fixture)
	if err != nil {
		t.Error(err)
	}

	if len(options) != 1 {
		t.Errorf("parsed %d options instead of 1", len(options))
	}

	parsed := options[0].(*ICMPOptionNonce)
	parsedMarshal, err := parsed.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsedMarshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsedMarshal)
	}

	option.Nonce = 281474976710656
	if _, err = option.Marshal(); err == nil {
		t.Errorf("expected out of boundaries error")
	}
}

func TestICMPOptionSourceLinkLayerAddress(t *testing.T) {
	var err error
	option := NewICMPOption(ICMPOptionTypeSourceLinkLayerAddress).(*ICMPOptionSourceLinkLayerAddress)
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

	descfix := "source link-layer address option (1), length 8 (1): a1:b2:c3:d4:e6:f7"
	desc := option.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	var options []ICMPOption
	options, err = parseOptions(fixture)
	if err != nil {
		t.Error(err)
	}

	if len(options) != 1 {
		t.Errorf("parsed %d options instead of 1", len(options))
	}

	parsed := options[0].(*ICMPOptionSourceLinkLayerAddress)
	parsedMarshal, err := parsed.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsedMarshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsedMarshal)
	}
}

func TestICMPOptionTargetLinkLayerAddress(t *testing.T) {
	var err error
	option := NewICMPOption(ICMPOptionTypeTargetLinkLayerAddress).(*ICMPOptionTargetLinkLayerAddress)
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

	descfix := "target link-layer Address option (2), length 8 (1): a1:b2:c3:d4:e6:f7"
	desc := option.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	var options []ICMPOption
	options, err = parseOptions(fixture)
	if err != nil {
		t.Error(err)
	}

	if len(options) != 1 {
		t.Errorf("parsed %d options instead of 1", len(options))
	}

	parsed := options[0].(*ICMPOptionTargetLinkLayerAddress)
	parsedMarshal, err := parsed.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsedMarshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsedMarshal)
	}
}

func TestICMPOptionPrefixInformation(t *testing.T) {
	option := NewICMPOption(ICMPOptionTypePrefixInformation).(*ICMPOptionPrefixInformation)
	option.PrefixLength = 64
	option.OnLink = true
	option.Auto = true
	option.ValidLifetime = 2592000
	option.PreferredLifetime = 604800
	option.Prefix = net.ParseIP("2a00:1450:400e:802::")

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

	descfix := "prefix info option (3), length 32 (4): 2a00:1450:400e:802::/64, Flags [onlink auto], valid time 2592000s, pref. time 604800s"
	desc := option.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	var options []ICMPOption
	options, err = parseOptions(fixture)
	if err != nil {
		t.Error(err)
	}

	if len(options) != 1 {
		t.Errorf("parsed %d options instead of 1", len(options))
	}

	parsed := options[0].(*ICMPOptionPrefixInformation)
	parsedMarshal, err := parsed.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsedMarshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsedMarshal)
	}
}

func TestICMPOptionRecursiveDNSServer(t *testing.T) {
	option := NewICMPOption(ICMPOptionTypeRecursiveDNSServer).(*ICMPOptionRecursiveDNSServer)
	option.Lifetime = 300
	option.Servers = []net.IP{net.ParseIP("2001:4860:4860::8844")}

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

	descfix := "rdnss option (25), length 24 (3): lifetime 300s, addr: 2001:4860:4860::8844"
	desc := option.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	var options []ICMPOption
	options, err = parseOptions(fixture)
	if err != nil {
		t.Error(err)
	}

	if len(options) != 1 {
		t.Errorf("parsed %d options instead of 1", len(options))
	}

	parsed := options[0].(*ICMPOptionRecursiveDNSServer)
	parsedMarshal, err := parsed.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsedMarshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsedMarshal)
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

	descfix = "rdnss option (25), length 40 (5): lifetime 300s, addr: 2001:4860:4860::8844 addr: 2001:4860:4860::8888"
	desc = option.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	options, err = parseOptions(fixture)
	if err != nil {
		t.Error(err)
	}

	if len(options) != 1 {
		t.Errorf("parsed %d options instead of 1", len(options))
	}

	parsed = options[0].(*ICMPOptionRecursiveDNSServer)
	parsedMarshal, err = parsed.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsedMarshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsedMarshal)
	}
}

func TestICMPOptionUnknown(t *testing.T) {
	option := &ICMPOptionUnknown{
		optionType:   100,
		optionLength: 1,
		body:         []byte{1, 2, 3, 4, 5, 6},
	}

	if option.Type() != 100 {
		t.Errorf("wrong type: %d instead of %d", option.Type(), 100)
	}

	if option.Len() != 1 {
		t.Errorf("wrong length, %d != 1", option.Len())
	}

	marshal, err := option.Marshal()
	if err != nil {
		t.Error(err)
	}

	// fixture describes
	// unknown option (100), length 8 (1)
	fixture := []byte{100, 1, 1, 2, 3, 4, 5, 6}
	if bytes.Compare(marshal, fixture) != 0 {
		t.Errorf("fixture of %v did not match %v", fixture, marshal)
	}

	descfix := "unknown option (100), length 8 (1)"
	desc := option.String()
	if strings.Compare(desc, descfix) != 0 {
		t.Errorf("fixture of '%s' did not match '%s'", descfix, desc)
	}

	var options []ICMPOption
	options, err = parseOptions(fixture)
	if err != nil {
		t.Error(err)
	}

	if len(options) != 1 {
		t.Errorf("parsed %d options instead of 1", len(options))
	}

	parsed := options[0].(*ICMPOptionUnknown)
	parsedMarshal, err := parsed.Marshal()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(parsedMarshal, marshal) != 0 {
		t.Errorf("marshal of %v did not match %v", marshal, parsedMarshal)
	}
}
