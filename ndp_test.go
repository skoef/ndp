package ndp

import (
	"bytes"
	"reflect"
	"testing"
)

func TestEncDecDomainName(t *testing.T) {
	tests := []struct {
		name    []string
		encoded []byte
	}{
		// TODO: fix this
		//{[]string{"."}, []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{[]string{"foo.bar."}, []byte{3, 102, 111, 111, 3, 98, 97, 114, 0, 0, 0, 0, 0, 0, 0, 0}},
		{[]string{"golang.org."}, []byte{6, 103, 111, 108, 97, 110, 103, 3, 111, 114, 103, 0, 0, 0, 0, 0}},
		{[]string{"basement.golang.org."}, []byte{8, 98, 97, 115, 101, 109, 101, 110, 116, 6, 103, 111, 108, 97, 110, 103, 3, 111, 114, 103, 0, 0, 0, 0}},
		{[]string{"basement.golang.org.", "golang.org."}, []byte{8, 98, 97, 115, 101, 109, 101, 110, 116, 6, 103, 111, 108, 97, 110, 103, 3, 111, 114, 103, 0, 6, 103, 111, 108, 97, 110, 103, 3, 111, 114, 103, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	for _, test := range tests {
		// encoding
		encoded := encDomainName(test.name)
		if bytes.Compare(encoded, test.encoded) != 0 {
			t.Errorf("failed to encode %s to %v, result was %v", test.name, test.encoded, encoded)
		}
		// decoding
		name := decDomainName(test.encoded)
		if !reflect.DeepEqual(name, test.name) {
			t.Errorf("failed to decode %v to %s, result was %s", test.encoded, test.name, name)
		}
	}

	// total length may not exceed 255 bytes
	encoded := encDomainName([]string{
		// many labels
		"aaaa.aaaa.aaaa",
		"bbbb.bbbb.bbbb",
		"cccc.cccc.cccc",
		"dddd.dddd.dddd",
		"eeee.eeee.eeee",
		"ffff.ffff.ffff",
		"gggg.gggg.gggg",
		"hhhh.hhhh.hhhh",
		"iiii.iiii.iiii",
		"jjjj.jjjj.jjjj",
		"kkkk.kkkk.kkkk",
		"llll.llll.llll",
		"mmmm.mmmm.mmmm",
		"nnnn.nnnn.nnnn",
		"oooo.oooo.oooo",
		"pppp.pppp.pppp",
		"qqqq.qqqq.qqqq",
	})
	if len(encoded) != 255 {
		t.Errorf("expected truncated encoding of 255, not %d", len(encoded))
	}

	// individual label length may not exceed 63 bytes
	encoded = encDomainName([]string{
		// very long label
		"abcdefghijlmnopqrstuvwyxzabcdefghijlmnopqrstuvwyxzabcdefghijlmnopqrstuvwyxz.foo",
	})
	if len(encoded) != 72 {
		t.Errorf("expected truncated encoding of 72, not %d", len(encoded))
	}
}
