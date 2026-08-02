package producer

import (
	"encoding/json"
	"fmt"
	"strings"

	"substore/internal/model"
)

// ProduceQX outputs Quantumult X [server_local] style entries.
func ProduceQX(proxies []*model.Proxy, _ map[string]any) (string, error) {
	lines := []string{"[server_local]"}
	for _, p := range proxies {
		if line := qxLine(p); line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n"), nil
}

func qxLine(p *model.Proxy) string {
	tag := p.GetString("name")
	if tag == "" {
		tag = p.Type()
	}
	base := fmt.Sprintf("%s=%s:%d", p.Type(), p.Server(), p.Port())
	switch p.Type() {
	case "ss":
		base += ", method=" + p.GetString("cipher") + ", password=" + p.GetString("password")
	case "trojan":
		base += ", password=" + p.GetString("password")
		if sni := p.GetString("sni"); sni != "" {
			base += ", tls-host=" + sni
		}
	case "vmess":
		base += ", method=chacha20-ietf-poly1305, password=" + p.GetString("uuid")
		if p.GetString("network") == "ws" {
			base += ", obfs=wss, obfs-host=" + p.GetString("ws-host") + ", obfs-uri=" + p.GetString("ws-path")
		}
	case "vless":
		base += ", method=chacha20-ietf-poly1305, password=" + p.GetString("uuid")
		if p.GetString("network") == "ws" {
			base += ", obfs=wss, obfs-host=" + p.GetString("ws-host") + ", obfs-uri=" + p.GetString("ws-path")
		}
	case "hysteria2":
		base += ", password=" + p.GetString("password")
		if sni := p.GetString("sni"); sni != "" {
			base += ", tls-host=" + sni
		}
	case "http", "https":
		base = fmt.Sprintf("http=%s:%d", p.Server(), p.Port())
		if u := p.GetString("username"); u != "" {
			base += ", username=" + u + ", password=" + p.GetString("password")
		}
	case "socks5", "socks":
		base = fmt.Sprintf("socks5=%s:%d", p.Server(), p.Port())
		if u := p.GetString("username"); u != "" {
			base += ", username=" + u + ", password=" + p.GetString("password")
		}
	default:
		return ""
	}
	if p.GetBool("udp") {
		base += ", udp-relay=true"
	}
	base += ", tag=" + tag
	return base
}

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

func singBoxOutbound(p *model.Proxy) any {
	base := map[string]any{"type": p.Type(), "tag": p.GetString("name")}
	switch p.Type() {
	case "ss":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		base["method"] = p.GetString("cipher")
		base["password"] = p.GetString("password")
	case "trojan":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		base["password"] = p.GetString("password")
		base["tls"] = map[string]any{"enabled": true, "server_name": p.GetString("sni")}
	case "vmess":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		base["uuid"] = p.GetString("uuid")
		base["alter_id"] = p.GetInt("alterId")
		base["security"] = "auto"
		if p.GetString("network") == "ws" {
			base["transport"] = map[string]any{
				"type": "ws",
				"path": p.GetString("ws-path"),
				"headers": map[string]any{"Host": p.GetString("ws-host")},
			}
		}
	case "vless":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		base["uuid"] = p.GetString("uuid")
		if p.GetString("network") == "ws" {
			base["transport"] = map[string]any{
				"type": "ws",
				"path": p.GetString("ws-path"),
				"headers": map[string]any{"Host": p.GetString("ws-host")},
			}
		}
	case "hysteria2":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		base["password"] = p.GetString("password")
		base["tls"] = map[string]any{"enabled": true, "server_name": p.GetString("sni")}
	case "tuic":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
		base["uuid"] = p.GetString("uuid")
		base["password"] = p.GetString("password")
		base["tls"] = map[string]any{"enabled": true, "server_name": p.GetString("sni")}
	case "socks5", "socks", "http":
		base["server"] = p.Server()
		base["server_port"] = p.Port()
	default:
		return nil
	}
	return base
}

// ProduceV2Ray outputs v2ray outbound configs.
func ProduceV2Ray(proxies []*model.Proxy, _ map[string]any) (string, error) {
	var outbounds []any
	for _, p := range proxies {
		o := v2rayOutbound(p)
		if o != nil {
			outbounds = append(outbounds, o)
		}
	}
	config := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{},
		"outbounds": outbounds,
	}
	b, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func v2rayOutbound(p *model.Proxy) any {
	base := map[string]any{
		"tag":      p.GetString("name"),
		"protocol": p.Type(),
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": p.Server(),
			"port":    p.Port(),
			"users":   []any{map[string]any{"id": p.GetString("uuid"), "alterId": p.GetInt("alterId")}},
		}}},
		"streamSettings": map[string]any{"network": p.GetString("network")},
	}
	if p.GetString("network") == "ws" {
		base["streamSettings"] = map[string]any{
			"network": "ws",
			"wsSettings": map[string]any{
				"path":    p.GetString("ws-path"),
				"headers": map[string]any{"Host": p.GetString("ws-host")},
			},
		}
	}
	if p.GetBool("tls") {
		base["streamSettings"].(map[string]any)["security"] = "tls"
		base["streamSettings"].(map[string]any)["tlsSettings"] = map[string]any{
			"serverName":    p.GetString("sni"),
			"allowInsecure": p.GetBool("skip-cert-verify"),
		}
	}
	switch p.Type() {
	case "ss", "trojan", "hysteria2", "tuic", "socks", "http":
		// settings differ; keep minimal
	}
	return base
}

// ProduceEgern outputs Egern-style entries (Surge-compatible).
func ProduceEgern(proxies []*model.Proxy, options map[string]any) (string, error) {
	return ProduceSurge(proxies, options)
}
