package ndp

import "strings"

// inspired by golang.org/net/dnsclient.go's absDomainName
func absDomainName(b []byte) string {
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

func encDomainName(n string) []byte {
	b := make([]byte, 0)
	// loop over each part of the domain name
	for _, p := range strings.Split(n, ".") {
		// length for this part
		b = append(b, uint8(len(p)))
		// append bytes for this part
		b = append(b, []byte(p)...)
	}
	// length 0 and 0 body for ending .
	b = append(b, 0, 0)
	return b
}
