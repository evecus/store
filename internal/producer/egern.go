package producer

import (
	"strings"

	"substore/internal/model"
)

// ProduceEgern outputs Egern-style proxy entries.
// Egern supports: http, https, socks5, ss, trojan, hysteria2, vless, vmess,
// tuic, wireguard, anytls, ssh, snell.
func ProduceEgern(proxies []*model.Proxy, _ map[string]any) (string, error) {
	lines := []string{}
	for _, p := range proxies {
		if line := egernLine(p); line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n"), nil
}

// egernSupportedTypes are the proxy types Egern can output.
var egernSupportedTypes = map[string]bool{
	"http": true, "https": true, "socks5": true, "ss": true,
	"trojan": true, "hysteria2": true, "vless": true,
	"vmess": true, "tuic": true, "wireguard": true,
	"anytls": true, "ssh": true, "snell": true,
}

// egernSSCiphers are the ciphers Egern accepts for SS.
var egernSSCiphers = map[string]bool{
	"chacha20-ietf-poly1305": true, "chacha20-poly1305": true,
	"aes-256-gcm": true, "aes-128-gcm": true, "none": true,
	"rc4": true, "rc4-md5": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
}

func egernLine(p *model.Proxy) string {
	typ := p.Type()
	if !egernSupportedTypes[typ] {
		return ""
	}
	if typ == "ss" && !egernSSCiphers[strings.ToLower(p.GetString("cipher"))] {
		return ""
	}
	// Egern uses the same format as Surge for most protocols
	line, err := surgeProduceLine(p, nil)
	if err != nil {
		return ""
	}
	return line
}
