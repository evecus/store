package parser

import (
	"fmt"
	"strings"

	"substore/internal/model"
)

func init() {
	MustRegister(
		&Parser{Name: "URI TUIC Parser",
			Test: func(line string) bool { return strings.HasPrefix(line, "tuic://") },
			Parse: func(line string) (*model.Proxy, error) {
				return parseTuic(strings.TrimPrefix(line, "tuic://"))
			},
		},
		&Parser{Name: "URI AnyTLS Parser",
			Test: func(line string) bool { return strings.HasPrefix(line, "anytls://") },
			Parse: func(line string) (*model.Proxy, error) {
				return parseAnyTLS(strings.TrimPrefix(line, "anytls://"))
			},
		},
		&Parser{Name: "URI WireGuard Parser",
			Test: func(line string) bool {
				return strings.HasPrefix(line, "wireguard://") || strings.HasPrefix(line, "wg://")
			},
			Parse: func(line string) (*model.Proxy, error) {
				payload := strings.TrimPrefix(line, "wireguard://")
				payload = strings.TrimPrefix(payload, "wg://")
				return parseWireGuard(payload)
			},
		},
	)
}

func parseTuic(payload string) (*model.Proxy, error) {
	content, name := DecodeURIFragment(payload)
	qIdx := strings.Index(content, "?")
	addrPart := content
	query := ""
	if qIdx != -1 {
		addrPart = content[:qIdx]
		query = content[qIdx+1:]
	}
	auth := ""
	atIdx := strings.Index(addrPart, "@")
	if atIdx != -1 {
		auth = addrPart[:atIdx]
		addrPart = addrPart[atIdx+1:]
	}
	host, port, ok := SplitHostPort(addrPart)
	if !ok || host == "" || port == "" {
		return nil, fmt.Errorf("invalid tuic server:port")
	}
	p := model.NewProxy()
	p.Set("type", "tuic")
	p.Set("server", host)
	p.Set("port", port)
	if auth != "" {
		p.Set("uuid", auth)
	}
	params := ParseURIParams(query)
	if params["sni"] != "" {
		p.Set("sni", params["sni"])
	}
	if params["allowInsecure"] == "1" || params["allowInsecure"] == "true" {
		p.Set("skip-cert-verify", true)
	}
	if params["alpn"] != "" {
		p.Set("alpn", strings.Split(params["alpn"], ","))
	}
	if params["congestion_control"] != "" {
		p.Set("congestion-controller", params["congestion_control"])
	}
	if params["udp_relay_mode"] != "" {
		p.Set("udp-relay-mode", params["udp_relay_mode"])
	}
	if params["fp"] != "" {
		p.Set("client-fingerprint", params["fp"])
	}
	if name != "" {
		p.Set("name", name)
	} else {
		p.Set("name", "TUIC "+host+":"+port)
	}
	return p, nil
}

func parseAnyTLS(payload string) (*model.Proxy, error) {
	content, name := DecodeURIFragment(payload)
	qIdx := strings.Index(content, "?")
	addrPart := content
	query := ""
	if qIdx != -1 {
		addrPart = content[:qIdx]
		query = content[qIdx+1:]
	}
	password := ""
	atIdx := strings.Index(addrPart, "@")
	if atIdx != -1 {
		password = addrPart[:atIdx]
		addrPart = addrPart[atIdx+1:]
	}
	host, port, ok := SplitHostPort(addrPart)
	if !ok || host == "" || port == "" {
		return nil, fmt.Errorf("invalid anytls server:port")
	}
	p := model.NewProxy()
	p.Set("type", "anytls")
	p.Set("server", host)
	p.Set("port", port)
	if password != "" {
		p.Set("password", password)
	}
	params := ParseURIParams(query)
	if params["sni"] != "" {
		p.Set("sni", params["sni"])
	}
	if params["allowInsecure"] == "1" || params["allowInsecure"] == "true" {
		p.Set("skip-cert-verify", true)
	}
	if params["alpn"] != "" {
		p.Set("alpn", strings.Split(params["alpn"], ","))
	}
	if params["fp"] != "" {
		p.Set("client-fingerprint", params["fp"])
	}
	if name != "" {
		p.Set("name", name)
	} else {
		p.Set("name", "AnyTLS "+host+":"+port)
	}
	return p, nil
}

func parseWireGuard(payload string) (*model.Proxy, error) {
	content, name := DecodeURIFragment(payload)
	// may be base64 encoded JSON (peers style) or wireguard URI params
	decoded := content
	if d, err := Base64Decode(content); err == nil && strings.Contains(d, "{") {
		decoded = d
	}

	p := model.NewProxy()
	p.Set("type", "wireguard")

	if strings.HasPrefix(decoded, "{") {
		var cfg map[string]any
		if err := JSONUnmarshalLoose(decoded, &cfg); err != nil {
			return nil, err
		}
		for _, key := range []string{"private-key", "private_key", "privateKey"} {
			if v, ok := cfg[key]; ok {
				p.Set("private-key", v)
				break
			}
		}
		for _, key := range []string{"self-ip", "self_ip", "selfIp"} {
			if v, ok := cfg[key]; ok {
				p.Set("self-ip", v)
				break
			}
		}
		for _, key := range []string{"server-ip", "server_ip", "serverIp"} {
			if v, ok := cfg[key]; ok {
				p.Set("server", v)
				break
			}
		}
		if v, ok := cfg["port"]; ok {
			p.Set("port", int(toFloat(v)))
		}
		if v, ok := cfg["server-public-key"]; ok {
			p.Set("public-key", v)
		} else if v, ok := cfg["server_pub_key"]; ok {
			p.Set("public-key", v)
		} else if v, ok := cfg["serverPublicKey"]; ok {
			p.Set("public-key", v)
		}
		if v, ok := cfg["preshared-key"]; ok {
			p.Set("preshared-key", v)
		}
		if v, ok := cfg["dns"]; ok {
			p.Set("dns", v)
		}
		if v, ok := cfg["mtu"]; ok {
			p.Set("mtu", int(toFloat(v)))
		}
		if v, ok := cfg["ip"]; ok {
			p.Set("ip", v)
		}
		if v, ok := cfg["ipv6"]; ok {
			p.Set("ipv6", v)
		}
	} else {
		// query style: ?address=...&private-key=...
		qIdx := strings.Index(decoded, "?")
		addrPart := decoded
		query := ""
		if qIdx != -1 {
			addrPart = decoded[:qIdx]
			query = decoded[qIdx+1:]
		}
		if addrPart != "" {
			p.Set("server", addrPart)
		}
		params := ParseURIParams(query)
		for key, target := range map[string]string{
			"address": "self-ip", "private-key": "private-key",
			"public-key": "public-key", "preshared-key": "preshared-key",
			"dns": "dns", "ip": "ip", "ipv6": "ipv6",
		} {
			if v := params[key]; v != "" {
				p.Set(target, v)
			}
		}
		if v := params["port"]; v != "" {
			p.Set("port", int(toFloat(v)))
		}
		if v := params["mtu"]; v != "" {
			p.Set("mtu", int(toFloat(v)))
		}
	}

	if p.GetString("server") == "" {
		return nil, fmt.Errorf("invalid wireguard link: missing server")
	}
	if name != "" {
		p.Set("name", name)
	} else {
		p.Set("name", "WireGuard "+p.Server())
	}
	normalizeWireGuardPeers(p)
	return p, nil
}

func normalizeWireGuardPeers(p *model.Proxy) {
	// build a peers list if ip/ipv6 present
	ips := []string{}
	if v := p.GetString("ip"); v != "" {
		ips = append(ips, v)
	}
	if v := p.GetString("ipv6"); v != "" {
		ips = append(ips, v)
	}
	if len(ips) > 0 {
		peer := map[string]any{"ip": ips[0]}
		if len(ips) > 1 {
			peer["ipv6"] = ips[1]
		}
		if pub := p.GetString("public-key"); pub != "" {
			peer["public-key"] = pub
		}
		p.Set("peers", []any{peer})
	}
	if p.GetString("self-ip") != "" {
		p.Set("self-ip", []any{p.GetString("self-ip")})
	}
}
