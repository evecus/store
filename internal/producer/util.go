package producer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

func base64StdEncode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func base64StdDecode(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawStdEncoding.DecodeString(s)
}

// jsonMarshalSorted marshals a map deterministically (Go sorts map keys).
func jsonMarshalSorted(m map[string]any) (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
