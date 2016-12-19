package ndp

import "strings"

// inspired by golang.org/net/dnsclient.go's absDomainName
func decDomainName(b []byte) []string {
	names := []string{}
	labels := []string{}
	for {
		// go over each label
		length := int(b[0])
		// extract new label
		if length > 0 {
			labels = append(labels, string(b[1:(length+1)]))
			// on null byte, join current labels and add to array
		} else if len(labels) > 0 {
			names = append(names, strings.Join(labels, ".")+".")
			labels = []string{}
		}
		b = b[(length + 1):]
		if len(b) == 0 {
			break
		}
	}

	return names
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
