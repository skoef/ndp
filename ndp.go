package ndp

import "strings"

// inspired by golang.org/net/dnsclient.go's absDomainName
func decDomainName(b []byte) string {
	name := ""
	start := 0
	for {
		length := int(b[start])
		if length > 0 {
			name += string(b[start+1:(start+length+1)]) + "."
		}

		start += (length + 1)
		if start >= len(b) {
			break
		}
	}

	// make sure we end with a dot
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	return name
}

// encode domain names as defined in RFC 1035 Section 3.1
func encDomainName(dn []string) []byte {
	b := make([]byte, 0)
	// loop over given domain names
	for _, n := range dn {
		// loop over each part of the domain name
		for _, p := range strings.Split(n, ".") {
			lab := make([]byte, 0)
			// length for this part
			lab = append(lab, uint8(len(p)))
			// append bytes for this part
			lab = append(lab, []byte(p)...)

			// cap label on 63 octets
			if len(lab) > 63 {
				lab = lab[:63]
			}

			b = append(b, lab...)
		}
	}

	// pad encoding until it's a multiple of octets
	pad := (8 - (len(b) % 8))
	for i := 0; i < pad; i++ {
		b = append(b, 0)
	}

	// cap encoding on 255 octets
	if len(b) > 255 {
		return b[:255]
	}

	return b
}
