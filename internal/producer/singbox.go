package producer

import (
	"encoding/json"
	"fmt"

	"substore/internal/model"
)

// ProduceSingBox outputs a sing-box outbounds JSON array.
func ProduceSingBox(proxies []*model.Proxy, _ map[string]any) (string, error) {
	var outbounds []any
	for _, p := range proxies {
		o := singBoxOutbound(p)
		if o != nil {
			outbounds = append(outbounds, o)
		}
	}
	b, err := json.MarshalIndent(outbounds, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// singBoxSupportedTypes are the proxy types sing-box can output.
var singBoxSupportedTypes = map[string]bool{
	"ss": true, "ssr": true, "vmess": true, "vless": true,
	"trojan": true, "hysteria": true, "hysteria2": true,
	"tuic": true, "wireguard": true, "anytls": true,
	"socks5": true, "socks": true, "http": true, "ssh": true,
	"shadowtls": true,
}

func singBoxOutbound(p *model.Proxy) any {
	typ := p.Type()
	if !singBoxSupportedTypes[typ] {
		return nil
	}

	base := map[string]any{
		"type": singBoxType(typ),
		"tag":  p.GetString("name"),
	}

	singBoxTLS := func() map[string]any {
		tls := map[string]any{"enabled": true}
		if sni := p.GetString("sni"); sni != "" {
			tls["server_name"] = sni
		}
		if p.GetBool("skip-cert-verify") {
			tls["insecure"] = true
		}
		if alpn := p.GetArray("alpn"); len(alpn) > 0 {
			tls["alpn"] = alpn
		}
		if fp := p.GetString("client-fingerprint"); fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		if ro := p.GetMap("reality-opts"); ro != nil {
			reality := map[string]any{"enabled": true}
			if pk := str(ro["public-key"]); pk != "" {
				reality["public_key"] = pk
			}
			if sid := str(ro["short-id"]); sid != "" {
				reality["short_id"] = sid
			}
			tls["reality"] = reality
		}
		return tls
	}

	switch typ {
	case "ss":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		base["method"] = p.GetString("cipher")
		base["password"] = p.GetString("password")
		// plugin
		if plugin := p.GetString("plugin"); plugin != "" {
			if plugin == "shadow-tls" {
				base["plugin"] = "shadowtls"
				if opts := p.GetMap("plugin-opts"); opts != nil {
					pluginOpts := map[string]any{}
					if h := str(opts["host"]); h != "" {
						pluginOpts["server"] = h
					}
					if pw := str(opts["password"]); pw != "" {
						pluginOpts["password"] = pw
					}
					if v := str(opts["version"]); v != "" {
						pluginOpts["version"] = v
					}
					base["plugin_opts"] = pluginOpts
				}
			}
		}
	case "ssr":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		base["method"] = p.GetString("cipher")
		base["password"] = p.GetString("password")
		base["protocol"] = p.GetString("protocol")
		base["obfs"] = p.GetString("obfs")
		if pp := p.GetString("protocol-param"); pp != "" {
			base["protocol_param"] = pp
		}
		if op := p.GetString("obfs-param"); op != "" {
			base["obfs_param"] = op
		}
	case "vmess":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		base["uuid"] = p.GetString("uuid")
		base["alter_id"] = p.GetInt("alterId")
		if cipher := p.GetString("cipher"); cipher != "" {
			base["security"] = cipher
		} else {
			base["security"] = "auto"
		}
		if p.GetBool("tls") {
			base["tls"] = singBoxTLS()
		}
		singBoxTransport(&base, p)
	case "vless":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		base["uuid"] = p.GetString("uuid")
		if flow := p.GetString("flow"); flow != "" {
			base["flow"] = flow
		}
		if p.GetBool("tls") || p.GetMap("reality-opts") != nil {
			base["tls"] = singBoxTLS()
		}
		singBoxTransport(&base, p)
	case "trojan":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		base["password"] = p.GetString("password")
		base["tls"] = singBoxTLS()
		singBoxTransport(&base, p)
	case "hysteria":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		if auth := p.GetString("auth"); auth != "" {
			base["auth_str"] = auth
		} else if authStr := p.GetString("auth-str"); authStr != "" {
			base["auth_str"] = authStr
		}
		if up := p.GetString("up"); up != "" {
			base["up_mbps"] = up
		}
		if down := p.GetString("down"); down != "" {
			base["down_mbps"] = down
		}
		if obfs := p.GetString("obfs"); obfs != "" {
			base["obfs"] = obfs
		}
		base["tls"] = singBoxTLS()
	case "hysteria2":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		base["password"] = p.GetString("password")
		if obfs := p.GetString("obfs"); obfs != "" {
			base["obfs"] = map[string]any{"type": obfs}
			if obfsPw := p.GetString("obfs-password"); obfsPw != "" {
				base["obfs"].(map[string]any)["password"] = obfsPw
			}
		}
		base["tls"] = singBoxTLS()
	case "tuic":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		base["uuid"] = p.GetString("uuid")
		if pw := p.GetString("password"); pw != "" {
			base["password"] = pw
		} else if token := p.GetString("token"); token != "" {
			base["token"] = token
		}
		if cc := p.GetString("congestion-controller"); cc != "" {
			base["congestion_control"] = cc
		}
		if um := p.GetString("udp-relay-mode"); um != "" {
			base["udp_relay_mode"] = um
		}
		if p.GetBool("tls") || true {
			base["tls"] = singBoxTLS()
		}
	case "wireguard":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		if pk := p.GetString("private-key"); pk != "" {
			base["private_key"] = pk
		}
		if ip := p.GetString("ip"); ip != "" {
			base["local_address"] = []any{ip}
		}
		if ipv6 := p.GetString("ipv6"); ipv6 != "" {
			la := base["local_address"].([]any)
			base["local_address"] = append(la, ipv6)
		}
		if mtu := p.GetInt("mtu"); mtu > 0 {
			base["mtu"] = mtu
		}
		if dns := p.GetArray("dns"); len(dns) > 0 {
			base["dns"] = dns
		}
		// peers
		if peers := p.GetArray("peers"); len(peers) > 0 {
			var sbPeers []any
			for _, peer := range peers {
				if m, ok := peer.(map[string]any); ok {
					sp := map[string]any{
						"server":     str(m["server"]),
						"server_port": int(toFloat64(m["port"])),
					}
					if pk := str(m["public-key"]); pk != "" {
						sp["public_key"] = pk
					}
					if psk := str(m["pre-shared-key"]); psk != "" {
						sp["pre_shared_key"] = psk
					}
					if allowed := m["allowed-ips"]; allowed != nil {
						if arr, ok := allowed.([]any); ok {
							sp["allowed_ips"] = arr
						}
					}
					sbPeers = append(sbPeers, sp)
				}
			}
			base["peers"] = sbPeers
		}
	case "anytls":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		if pw := p.GetString("password"); pw != "" {
			base["password"] = pw
		}
		base["tls"] = singBoxTLS()
	case "socks5", "socks":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		if u := p.GetString("username"); u != "" {
			base["username"] = u
			base["password"] = p.GetString("password")
		}
		if p.GetBool("tls") {
			base["tls"] = singBoxTLS()
		}
	case "http":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		if u := p.GetString("username"); u != "" {
			base["username"] = u
			base["password"] = p.GetString("password")
		}
		if p.GetBool("tls") {
			base["tls"] = singBoxTLS()
		}
	case "ssh":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		base["user"] = p.GetString("username")
		if pw := p.GetString("password"); pw != "" {
			base["password"] = pw
		}
		if key := p.GetString("private-key"); key != "" {
			base["private_key"] = key
		}
		base["tls"] = singBoxTLS()
	case "shadowtls":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		if pw := p.GetString("password"); pw != "" {
			base["password"] = pw
		}
		base["tls"] = singBoxTLS()
	}

	// multiplex (smux)
	if smux := p.GetMap("smux"); smux != nil {
		if enabled, _ := smux["enabled"].(bool); enabled {
			multiplex := map[string]any{"enabled": true}
			if proto := str(smux["protocol"]); proto != "" {
				multiplex["protocol"] = proto
			}
			if mc := smux["max-connections"]; mc != nil {
				multiplex["max_connections"] = int(toFloat64(mc))
			}
			if ms := smux["max-streams"]; ms != nil {
				multiplex["max_streams"] = int(toFloat64(ms))
			}
			if padding, _ := smux["padding"].(bool); padding {
				multiplex["padding"] = true
			}
			base["multiplex"] = multiplex
		}
	}

	// tfo
	if p.GetBool("tfo") {
		base["tcp_fast_open"] = true
	}

	return base
}

// singBoxType maps proxy type to sing-box outbound type.
func singBoxType(typ string) string {
	switch typ {
	case "ss":
		return "shadowsocks"
	case "ssr":
		return "shadowsocksr"
	case "socks5", "socks":
		return "socks"
	case "anytls":
		return "anytls"
	default:
		return typ
	}
}

// singBoxTransport adds transport configuration (ws, grpc, http, h2) to the
// sing-box outbound.
func singBoxTransport(base *map[string]any, p *model.Proxy) {
	network := p.GetString("network")
	if network == "" || network == "tcp" {
		return
	}

	switch network {
	case "ws":
		transport := map[string]any{"type": "ws"}
		if wsOpts := p.GetMap("ws-opts"); wsOpts != nil {
			if path := str(wsOpts["path"]); path != "" {
				transport["path"] = path
			}
			if h := hostFromOpts(wsOpts); h != "" {
				transport["headers"] = map[string]any{"Host": h}
			}
			if ed, ok := wsOpts["max-early-data"]; ok {
				transport["max_early_data"] = int(toFloat64(ed))
			}
			if edhn := str(wsOpts["early-data-header-name"]); edhn != "" {
				transport["early_data_header_name"] = edhn
			}
			if v, _ := wsOpts["v2ray-http-upgrade"].(bool); v {
				transport["type"] = "httpupgrade"
				if h := hostFromOpts(wsOpts); h != "" {
					transport["host"] = h
				}
				delete(transport, "headers")
			}
		}
		(*base)["transport"] = transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if g := p.GetMap("grpc-opts"); g != nil {
			if sn := str(g["grpc-service-name"]); sn != "" {
				transport["service_name"] = sn
			}
		}
		(*base)["transport"] = transport
	case "http", "h2":
		transport := map[string]any{"type": "http"}
		if h2Opts := p.GetMap(network + "-opts"); h2Opts != nil {
			if path := str(h2Opts["path"]); path != "" {
				transport["path"] = path
			}
			if host := str(h2Opts["host"]); host != "" {
				if arr, ok := h2Opts["host"].([]any); ok {
					if len(arr) > 0 {
						transport["host"] = str(arr[0])
					}
				} else {
					transport["host"] = host
				}
			}
			if headers := h2Opts["headers"]; headers != nil {
				if hm, ok := headers.(map[string]any); ok {
					transport["headers"] = hm
				}
			}
		}
		if network == "h2" {
			// h2 requires TLS
			tls, ok := (*base)["tls"].(map[string]any)
			if !ok {
				tls = map[string]any{"enabled": true}
			}
			tls["enabled"] = true
			(*base)["tls"] = tls
		}
		(*base)["transport"] = transport
	case "httpupgrade":
		transport := map[string]any{"type": "httpupgrade"}
		if wsOpts := p.GetMap("ws-opts"); wsOpts != nil {
			if path := str(wsOpts["path"]); path != "" {
				transport["path"] = path
			}
			if h := hostFromOpts(wsOpts); h != "" {
				transport["host"] = h
			}
		}
		(*base)["transport"] = transport
	case "quic":
		transport := map[string]any{"type": "quic"}
		(*base)["transport"] = transport
	}
}

func toFloat64(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		var f float64
		_, _ = fmt.Sscan(t, &f)
		return f
	default:
		return 0
	}
}

// ProduceV2Ray outputs a base64-encoded URI list — the "通用订阅" format
// used by v2rayN-style subscription clients. This mirrors Sub-Store's
// V2Ray producer, which simply encodes the URI list in base64.
func ProduceV2Ray(proxies []*model.Proxy, opts map[string]any) (string, error) {
	plain, err := ProduceURI(proxies, opts)
	if err != nil {
		return "", err
	}
	return base64StdEncode([]byte(plain)), nil
}
