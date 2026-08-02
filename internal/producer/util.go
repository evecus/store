package producer

import (
	"encoding/base64"
	"strings"
)

func base64StdEncode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func base64StdDecode(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawStdEncoding.DecodeString(s)
}
