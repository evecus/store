package parser

import (
	"fmt"
	"strings"

	"substore/internal/model"
)

func init() {
	MustRegister(
		&Parser{Name: "QX Line Parser",
			Test: func(line string) bool {
				key := strings.SplitN(line, "=", 2)[0]
				return qxTypes[key]
			},
			Parse: parseQXLine,
		},
		&Parser{Name: "QX VMess Parser",
			Test: func(line string) bool {
				return strings.HasPrefix(line, "vmess://")
			},
			Parse: func(line string) (*model.Proxy, error) {
				return parseVMess(strings.TrimPrefix(line, "vmess://"))
			},
		},
	)
}

var qxTypes = map[string]bool{
	"shadowsocks": true, "ss": true, "http": true, "socks5": true,
	"trojan": true, "vless": true, "anytls": true, "hysteria2": true,
	"wireguard": true, "hy2": true,
}

func parseQXLine(line string) (*model.Proxy, error) {
	parts := strings.SplitN(line, "=", 2)
	typ := strings.TrimSpace(parts[0])
	fields := splitSurgeFields(parts[1])

	switch typ {
	case "shadowsocks", "ss":
		// server:port, method, password, fast-open=false, udp-relay=true
		if len(fields) < 3 {
			return nil, fmt.Errorf("invalid qx ss line")
		}
		host, port, ok := SplitHostPort(strings.TrimSpace(fields[0]))
		if !ok {
			return nil, fmt.Errorf("invalid qx ss server:port")
		}
		p := model.NewProxy()
		p.Set("type", "ss")
		p.Set("server", host)
		p.Set("port", port)
		p.Set("cipher", strings.TrimSpace(fields[1]))
		p.Set("password", strings.Trim(strings.TrimSpace(fields[2]), `"`))
		applyQXPairs(p, fields[3:])
		p.Set("name", buildQXName(p, "SS"))
		return p, nil
	case "http":
		if len(fields) < 3 {
			return nil, fmt.Errorf("invalid qx http line")
		}
		host, port, ok := SplitHostPort(strings.TrimSpace(fields[0]))
		if !ok {
			return nil, fmt.Errorf("invalid qx http server:port")
		}
		p := model.NewProxy()
		p.Set("type", "http")
		p.Set("server", host)
		p.Set("port", port)
		p.Set("username", strings.TrimSpace(fields[1]))
		p.Set("password", strings.TrimSpace(fields[2]))
		applyQXPairs(p, fields[3:])
		p.Set("name", buildQXName(p, "HTTP"))
		return p, nil
	case "socks5":
		if len(fields) < 3 {
			return nil, fmt.Errorf("invalid qx socks5 line")
		}
		host, port, ok := SplitHostPort(strings.TrimSpace(fields[0]))
		if !ok {
			return nil, fmt.Errorf("invalid qx socks5 server:port")
		}
		p := model.NewProxy()
		p.Set("type", "socks5")
		p.Set("server", host)
		p.Set("port", port)
		p.Set("username", strings.TrimSpace(fields[1]))
		p.Set("password", strings.TrimSpace(fields[2]))
		applyQXPairs(p, fields[3:])
		p.Set("name", buildQXName(p, "SOCKS5"))
		return p, nil
	case "trojan":
		// server:port, password, over-tls=true, tls-host=...
		if len(fields) < 2 {
			return nil, fmt.Errorf("invalid qx trojan line")
		}
		host, port, ok := SplitHostPort(strings.TrimSpace(fields[0]))
		if !ok {
			return nil, fmt.Errorf("invalid qx trojan server:port")
		}
		p := model.NewProxy()
		p.Set("type", "trojan")
		p.Set("server", host)
		p.Set("port", port)
		p.Set("password", strings.Trim(strings.TrimSpace(fields[1]), `"`))
		applyQXPairs(p, fields[2:])
		p.Set("tls", true)
		p.Set("name", buildQXName(p, "Trojan"))
		return p, nil
	case "vless", "anytls":
		if len(fields) < 2 {
			return nil, fmt.Errorf("invalid qx %s line", typ)
		}
		host, port, ok := SplitHostPort(strings.TrimSpace(fields[0]))
		if !ok {
			return nil, fmt.Errorf("invalid qx %s server:port", typ)
		}
		p := model.NewProxy()
		p.Set("type", typ)
		p.Set("server", host)
		p.Set("port", port)
		p.Set("password", strings.Trim(strings.TrimSpace(fields[1]), `"`))
		applyQXPairs(p, fields[2:])
		p.Set("name", buildQXName(p, strings.ToUpper(typ)))
		return p, nil
	case "hysteria2", "hy2":
		if len(fields) < 2 {
			return nil, fmt.Errorf("invalid qx hysteria2 line")
		}
		host, port, ok := SplitHostPort(strings.TrimSpace(fields[0]))
		if !ok {
			return nil, fmt.Errorf("invalid qx hysteria2 server:port")
		}
		p := model.NewProxy()
		p.Set("type", "hysteria2")
		p.Set("server", host)
		p.Set("port", port)
		p.Set("password", strings.Trim(strings.TrimSpace(fields[1]), `"`))
		applyQXPairs(p, fields[2:])
		p.Set("name", buildQXName(p, "Hysteria2"))
		return p, nil
	case "wireguard":
		return parseQXWireGuard(fields)
	}
	return nil, fmt.Errorf("unsupported qx type: %s", typ)
}

func applyQXPairs(p *model.Proxy, pairs []string) {
	for _, f := range pairs {
		f = strings.TrimSpace(f)
		if idx := strings.Index(f, "="); idx != -1 {
			key := strings.TrimSpace(f[:idx])
			val := strings.Trim(strings.TrimSpace(f[idx+1:]), `"`)
			switch key {
			case "fast-open":
				p.Set("tfo", isTrue(val))
			case "udp-relay":
				p.Set("udp", isTrue(val))
			case "over-tls":
				p.Set("tls", isTrue(val))
			case "tls-host", "sni":
				p.Set("sni", val)
			case "tls-verification":
				p.Set("skip-cert-verify", !isTrue(val))
			case "obfs":
				if val == "wss" {
					p.Set("tls", true)
				} else if strings.HasPrefix(val, "ws") {
					p.Set("network", "ws")
					if !p.Has("ws-opts") {
						p.Set("ws-opts", map[string]any{})
					}
				}
			case "obfs-path":
				p.Set("network", "ws")
				opts := p.GetMap("ws-opts")
				if opts == nil {
					opts = map[string]any{}
					p.Set("ws-opts", opts)
				}
				opts["path"] = val
			case "obfs-header":
				if strings.Contains(val, "Host:") {
					host := val
					if idx := strings.Index(host, "Host:"); idx != -1 {
						host = host[idx+5:]
					}
					if idx := strings.Index(host, "\r\n"); idx != -1 {
						host = host[:idx]
					}
					opts := p.GetMap("ws-opts")
					if opts == nil {
						opts = map[string]any{}
						p.Set("ws-opts", opts)
					}
					opts["headers"] = map[string]any{"Host": strings.TrimSpace(host)}
				}
			default:
				p.Set(key, val)
			}
		}
	}
}

func buildQXName(p *model.Proxy, fallback string) string {
	if n := p.GetString("name"); n != "" {
		return n
	}
	return fmt.Sprintf("%s %s:%d", fallback, p.Server(), p.Port())
}

func parseQXWireGuard(fields []string) (*model.Proxy, error) {
	// wireguard=server, port, private-key=..., ...
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid qx wireguard line")
	}
	p := model.NewProxy()
	p.Set("type", "wireguard")
	p.Set("server", strings.TrimSpace(fields[0]))
	p.Set("port", strings.TrimSpace(fields[1]))
	for _, f := range fields[2:] {
		f = strings.TrimSpace(f)
		if idx := strings.Index(f, "="); idx != -1 {
			key := strings.TrimSpace(f[:idx])
			val := strings.Trim(strings.TrimSpace(f[idx+1:]), `"`)
			p.Set(key, val)
		}
	}
	p.Set("name", "WireGuard "+p.Server())
	return p, nil
}
