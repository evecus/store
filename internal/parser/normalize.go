package parser

import (
	"strings"

	"substore/internal/model"
)

// normalizeProxy applies post-parse normalization, mirroring the original
// Sub-Store lastParse() logic.
func normalizeProxy(p *model.Proxy) {
	normalizeOptKeys(p)
	if p.Has("udp") {
		v := strings.ToLower(p.GetString("udp"))
		p.Set("udp", !(v == "false" || v == "off" || v == "0"))
	}
	if c := p.GetString("cipher"); c != "" {
		p.Set("cipher", strings.ToLower(c))
	}
	if p.Has("interface") {
		p.Set("interface-name", p.Get("interface"))
		p.Delete("interface")
	}
	if port := p.GetInt("port"); port > 0 {
		p.Set("port", port)
	}
	if s := p.GetString("server"); s != "" {
		p.Set("server", strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(s), "]"), "["))
	}
	// network defaults
	switch p.Type() {
	case "trojan":
		if !p.Has("network") {
			p.Set("network", "tcp")
		}
	case "vmess":
		if !p.Has("network") {
			p.Set("network", "tcp")
		}
		if !p.Has("cipher") {
			p.Set("cipher", "none")
		}
		if p.GetInt("alterId") == 0 && !p.Has("alterId") {
			p.Set("alterId", 0)
		}
	case "vless":
		if !p.Has("network") {
			p.Set("network", "tcp")
		}
	}

	// tls defaults for certain types
	tlsTypes := map[string]bool{
		"trojan": true, "tuic": true, "hysteria": true, "hysteria2": true,
		"juicity": true, "anytls": true, "trusttunnel": true, "h2-connect": true,
		"naive": true, "masque": true, "shadowquic": true,
	}
	if tlsTypes[p.Type()] {
		p.Set("tls", true)
	}

	// ws-opts normalization
	if p.GetString("network") == "ws" {
		if !p.Has("ws-opts") && (p.Has("ws-path") || p.Has("ws-headers")) {
			opts := map[string]any{}
			if p.Has("ws-path") {
				opts["path"] = p.Get("ws-path")
			}
			if p.Has("ws-headers") {
				opts["headers"] = p.Get("ws-headers")
			}
			p.Set("ws-opts", opts)
		}
		p.Delete("ws-path")
		p.Delete("ws-headers")
	}

	// path normalization
	network := p.GetString("network")
	if network != "" {
		opts := p.GetMap(network + "-opts")
		if opts != nil {
			if path, ok := opts["path"]; ok {
				opts["path"] = normalizeTransportPath(path)
			}
		}
	}

	// sni fallback for tls proxies
	if p.GetBool("tls") && !p.Has("sni") {
		if network != "" {
			opts := p.GetMap(network + "-opts")
			if opts != nil {
				if headers, ok := opts["headers"].(map[string]any); ok {
					if host, ok := headers["Host"].(string); ok && host != "" {
						p.Set("sni", host)
					}
				}
			}
		}
		if !p.Has("sni") && !isIPString(p.GetString("server")) {
			p.Set("sni", p.GetString("server"))
		}
	}

	// hysteria2 obfs
	if p.Type() == "hysteria2" {
		obfs := p.GetString("obfs")
		if obfs != "" && obfs != "salamander" && !p.Has("obfs-password") {
			p.Set("obfs-password", obfs)
			p.Set("obfs", "salamander")
		}
	}

	// disable-sni
	if p.GetString("sni") == "" || p.GetString("sni") == "off" {
		p.Set("disable-sni", true)
	}

	// tuic defaults
	if p.Type() == "tuic" {
		if !p.Has("alpn") {
			p.Set("alpn", []any{"h3"})
		}
		if !p.Has("congestion-controller") {
			p.Set("congestion-controller", "cubic")
		}
		if !p.Has("udp-relay-mode") {
			p.Set("udp-relay-mode", "native")
		}
	}

	// ws/http/h2 default paths
	if network == "ws" || network == "h2" {
		opts := p.GetMap(network + "-opts")
		if opts == nil {
			opts = map[string]any{}
			p.Set(network+"-opts", opts)
		}
		if _, ok := opts["path"]; !ok {
			opts["path"] = "/"
		}
	}

	// name decoding
	name := p.GetString("name")
	if name == "" {
		p.Set("name", p.Type()+" "+p.Server()+":"+string(rune(p.Port())))
	}
}

func normalizeOptKeys(p *model.Proxy) {
	for _, key := range keysOf(p.Fields()) {
		if strings.HasSuffix(strings.ToLower(key), "-opts") && key != strings.ToLower(key) {
			p.Set(strings.ToLower(key), p.Get(key))
			p.Delete(key)
		}
		// normalize subkeys of -opts maps to lowercase
		if strings.HasSuffix(key, "-opts") {
			if m, ok := p.Get(key).(map[string]any); ok {
				for _, k2 := range keysOf(m) {
					if k2 != strings.ToLower(k2) {
						if _, exists := m[strings.ToLower(k2)]; !exists {
							m[strings.ToLower(k2)] = m[k2]
						}
						delete(m, k2)
					}
				}
			}
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func normalizeTransportPath(path any) any {
	s, ok := path.(string)
	if !ok {
		return path
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "/"
	}
	if !strings.HasPrefix(s, "/") {
		return "/" + s
	}
	return s
}
