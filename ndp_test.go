package ndp

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncDecDomainName(t *testing.T) {
	tests := []struct {
		name    string
		encoded []byte
	}{
		{".", []byte{0, 0, 0, 0}},
		{"foo.bar.", []byte{3, 102, 111, 111, 3, 98, 97, 114, 0, 0, 0}},
		{"golang.org.", []byte{6, 103, 111, 108, 97, 110, 103, 3, 111, 114, 103, 0, 0, 0}},
	}

	for _, test := range tests {
		// encoding
		encoded := encDomainName(test.name)
		if bytes.Compare(encoded, test.encoded) != 0 {
			t.Errorf("failed to encode %s to %v, result was %v", test.name, test.encoded, encoded)
		}
		// decoding
		name := absDomainName(test.encoded)
		if strings.Compare(name, test.name) != 0 {
			t.Errorf("failed to decode %v to %s, result was %s", test.encoded, test.name, name)
		}
	}
}
