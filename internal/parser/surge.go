package parser

import (
	"fmt"
	"strings"

	"substore/internal/model"
)

func init() {
	MustRegister(
		&Parser{Name: "Surge Line Parser",
			Test: func(line string) bool {
				// name = type, server, port, ...
				if !strings.Contains(line, "=") {
					return false
				}
				parts := strings.SplitN(line, "=", 2)
				fields := strings.Split(parts[1], ",")
				if len(fields) < 3 {
					return false
				}
				typ := strings.TrimSpace(fields[0])
				return surgeTypes[typ]
			},
			Parse: parseSurgeLine,
		},
	)
}

var surgeTypes = map[string]bool{
	"direct": true, "ss": true, "ssr": true, "vmess": true, "trojan": true, "http": true,
	"https": true, "socks5": true, "socks5-tls": true, "snell": true,
	"tuic": true, "hysteria2": true, "hysteria": true, "wireguard": true,
	"vless": true, "anytls": true, "h2-connect": true, "trusttunnel": true,
	"external": true,
}

func parseSurgeLine(line string) (*model.Proxy, error) {
	parts := strings.SplitN(line, "=", 2)
	name := strings.TrimSpace(parts[0])
	fields := splitSurgeFields(parts[1])
	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid surge line")
	}
	typ := strings.TrimSpace(fields[0])
	server := strings.TrimSpace(fields[1])
	port := strings.TrimSpace(fields[2])
	p := model.NewProxy()
	p.Set("type", typ)
	p.Set("name", name)
	p.Set("server", server)
	p.Set("port", port)

	// key=value pairs
	params := map[string]string{}
	for _, f := range fields[3:] {
		f = strings.TrimSpace(f)
		if idx := strings.Index(f, "="); idx != -1 {
			params[strings.TrimSpace(f[:idx])] = strings.TrimSpace(f[idx+1:])
		}
	}
	for k, v := range params {
		p.Set(k, v)
	}
	// remove empty common values
	if p.GetString("encrypt-method") != "" {
		p.Set("cipher", p.GetString("encrypt-method"))
		p.Delete("encrypt-method")
	}
	if p.GetString("sni") != "" || p.GetString("peer") != "" {
		if p.GetString("peer") != "" && p.GetString("sni") == "" {
			p.Set("sni", p.GetString("peer"))
		}
		p.Delete("peer")
	}
	if p.GetString("tls") != "" {
		p.Set("tls", p.GetString("tls") != "false")
	}
	if p.GetString("udp") != "" {
		p.Set("udp", isTrue(p.GetString("udp")))
	}
	return p, nil
}

func splitSurgeFields(s string) []string {
	out := []string{}
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch r {
		case '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case ',':
			if inQuote {
				cur.WriteRune(r)
			} else {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	out = append(out, cur.String())
	return out
}
