package parser

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"substore/internal/model"
)

func init() {
	MustRegister(&Parser{
		Name: "URI SS Parser",
		Test: func(line string) bool { return strings.HasPrefix(line, "ss://") },
		Parse: func(line string) (*model.Proxy, error) {
			return parseSS(strings.TrimPrefix(line, "ss://"))
		},
	})
}

func parseSS(payload string) (*model.Proxy, error) {
	content, name := DecodeURIFragment(payload)
	p := model.NewProxy()
	p.Set("type", "ss")

	// userinfo@host:port form
	atIdx := strings.Index(content, "@")
	var userInfoStr, serverAndPort string
	query := ""

	if atIdx != -1 {
		userInfoStr = content[:atIdx]
		serverAndPort = content[atIdx+1:]
		if qIdx := strings.Index(serverAndPort, "?"); qIdx != -1 {
			query = serverAndPort[qIdx:]
			serverAndPort = serverAndPort[:qIdx]
		}
	} else {
		// legacy: base64(method:password@host:port)
		decoded, err := Base64Decode(content)
		if err != nil {
			return nil, err
		}
		if qIdx := strings.Index(decoded, "?"); qIdx != -1 {
			query = decoded[qIdx:]
			decoded = decoded[:qIdx]
		}
		at2 := strings.Index(decoded, "@")
		if at2 == -1 {
			return nil, fmt.Errorf("invalid ss link")
		}
		userInfoStr = decoded[:at2]
		serverAndPort = decoded[at2+1:]
	}

	params := ParseURIParams(query)

	// decode userinfo: may be base64 or method:password
	userInfo := decodeSSUserInfo(userInfoStr)
	ui := strings.SplitN(userInfo, ":", 2)
	if len(ui) != 2 {
		return nil, fmt.Errorf("invalid ss userinfo")
	}
	p.Set("cipher", ui[0])
	p.Set("password", ui[1])

	host, port, ok := SplitHostPort(serverAndPort)
	if !ok || host == "" || port == "" {
		return nil, fmt.Errorf("invalid ss server:port")
	}
	p.Set("server", host)
	p.Set("port", port)

	// query params
	if sec := params["security"]; sec != "" && sec != "none" {
		p.Set("tls", true)
	}
	if params["allowInsecure"] != "" {
		p.Set("skip-cert-verify", true)
	}
	if params["sni"] != "" {
		p.Set("sni", params["sni"])
	}
	if params["peer"] != "" && !p.Has("sni") {
		p.Set("sni", params["peer"])
	}
	if params["fp"] != "" {
		p.Set("client-fingerprint", params["fp"])
	}
	if params["alpn"] != "" {
		p.Set("alpn", strings.Split(params["alpn"], ","))
	}
	if params["udp"] != "" {
		p.Set("udp", true)
	}
	if params["uot"] == "1" || params["uot"] == "true" {
		p.Set("udp-over-tcp", true)
	}
	if params["tfo"] == "1" || params["tfo"] == "true" {
		p.Set("tfo", true)
	}

	// transport type
	if t := params["type"]; t != "" {
		network := t
		if network == "httpupgrade" {
			network = "ws"
			wsOpts := map[string]any{"v2ray-http-upgrade": true}
			p.Set("ws-opts", wsOpts)
		}
		p.Set("network", network)
		opts := map[string]any{}
		if path := params["path"]; path != "" {
			opts["path"] = path
		}
		if host := params["host"]; host != "" {
			opts["headers"] = map[string]any{"Host": host}
		}
		if len(opts) > 0 {
			p.Set(network+"-opts", opts)
		}
		if params["security"] == "reality" {
			ropts := map[string]any{}
			if v := params["pbk"]; v != "" {
				ropts["public-key"] = v
			}
			if v := params["sid"]; v != "" {
				ropts["short-id"] = v
			}
			if len(ropts) > 0 {
				p.Set("reality-opts", ropts)
			}
		}
	}

	// plugins
	parseSSPlugins(content, query, p)

	if name != "" {
		p.Set("name", name)
	} else {
		p.Set("name", "SS "+host+":"+port)
	}
	return p, nil
}

func decodeSSUserInfo(raw string) string {
	// raw may be "method:password" (possibly url-encoded) or base64
	if idx := strings.Index(raw, ":"); idx != -1 {
		left := decodeURIComponent(raw[:idx])
		right := decodeURIComponent(raw[idx+1:])
		return left + ":" + right
	}
	decoded := decodeURIComponent(raw)
	if strings.Contains(decoded, ":") {
		return decoded
	}
	if d, err := Base64Decode(decoded); err == nil {
		return d
	}
	return decoded
}

func parseSSPlugins(content, query string, p *model.Proxy) {
	// plugin=... query param (percent encoded, semicolon separated)
	qIdx := strings.Index(content, "?")
	full := content
	if qIdx != -1 {
		full = content[qIdx+1:]
	} else if query != "" {
		full = strings.TrimPrefix(query, "?")
	}
	for _, pair := range strings.Split(full, "&") {
		if !strings.HasPrefix(pair, "plugin=") {
			continue
		}
		pluginStr := decodeURIComponent(strings.TrimPrefix(pair, "plugin="))
		fields := strings.Split(pluginStr, ";")
		params := map[string]string{}
		for _, f := range fields {
			if f == "" {
				continue
			}
			if idx := strings.Index(f, "="); idx != -1 {
				params[f[:idx]] = strings.ReplaceAll(f[idx+1:], "\\=", "=")
			} else {
				params[f] = "true"
			}
		}
		switch params["plugin"] {
		case "obfs-local", "simple-obfs":
			p.Set("plugin", "obfs")
			p.Set("plugin-opts", map[string]any{
				"mode": params["obfs"],
				"host": params["obfs-host"],
			})
		case "v2ray-plugin":
			p.Set("plugin", "v2ray-plugin")
			mode := params["obfs"]
			if mode == "" {
				mode = params["mode"]
			}
			if mode == "" {
				mode = "websocket"
			}
			p.Set("plugin-opts", map[string]any{
				"mode":             mode,
				"host":             firstNonEmpty(params["obfs-host"], params["host"]),
				"path":             params["path"],
				"tls":              params["tls"] == "true" || params["tls"] == "1",
				"sni":              params["sni"],
				"skip-cert-verify": params["skip-cert-verify"] == "1" || params["skip-cert-verify"] == "true",
			})
		case "shadow-tls":
			p.Set("plugin", "shadow-tls")
			opts := map[string]any{
				"host":     params["host"],
				"password": params["password"],
			}
			if v := params["version"]; v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					opts["version"] = n
				}
			}
			p.Set("plugin-opts", opts)
		}
	}

	// shadow-tls=... (Shadowrocket style, JSON base64)
	if idx := strings.Index(full, "shadow-tls="); idx != -1 {
		raw := full[idx+len("shadow-tls="):]
		if end := strings.Index(raw, "&"); end != -1 {
			raw = raw[:end]
		}
		if d, err := Base64Decode(raw); err == nil {
			var cfg map[string]any
			if err := json.Unmarshal([]byte(d), &cfg); err == nil {
				opts := map[string]any{
					"host":     getString(cfg, "host"),
					"password": getString(cfg, "password"),
				}
				if v, ok := cfg["version"].(float64); ok {
					opts["version"] = int(v)
				}
				p.Set("plugin", "shadow-tls")
				p.Set("plugin-opts", opts)
				if a := getString(cfg, "address"); a != "" {
					p.Set("server", a)
				}
				if pt := getString(cfg, "port"); pt != "" {
					if n, err := strconv.Atoi(pt); err == nil {
						p.Set("port", n)
					}
				}
			}
		}
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func decodeURIComponent(s string) string {
	decoded := strings.ReplaceAll(s, "+", "%20")
	if out, err := urlUnescape(decoded); err == nil {
		return out
	}
	return s
}
