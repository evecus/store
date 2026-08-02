package producer

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"substore/internal/model"
)

// ProduceClashYAML outputs a full Clash/Mihomo config with proxies,
// proxy-groups and default rules.
func ProduceClashYAML(proxies []*model.Proxy, options map[string]any) (string, error) {
	var proxyList []any
	for _, p := range proxies {
		data := p.Data()
		if name, ok := data["name"]; !ok || fmt.Sprint(name) == "" {
			data["name"] = p.Type()
		}
		proxyList = append(proxyList, data)
	}

	names := make([]string, 0, len(proxies))
	for _, p := range proxies {
		names = append(names, p.GetString("name"))
	}

	config := map[string]any{
		"port":               7890,
		"socks-port":         7891,
		"allow-lan":          false,
		"mode":               "rule",
		"log-level":          "info",
		"external-controller": "127.0.0.1:9090",
		"proxies":            proxyList,
		"proxy-groups": []any{
			map[string]any{
				"name":    "PROXY",
				"type":    "select",
				"proxies": append([]string{"DIRECT"}, names...),
			},
			map[string]any{
				"name":    "auto",
				"type":    "url-test",
				"proxies": names,
				"url":     "http://www.gstatic.com/generate_204",
				"interval": 300,
			},
		},
		"rules": []any{
			"MATCH,PROXY",
		},
	}

	includeRules, _ := options["includeRules"].(bool)
	if !includeRules {
		delete(config, "rules")
	}

	b, err := yaml.Marshal(config)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ProduceStash is an alias of ProduceClashYAML.
func ProduceStash(proxies []*model.Proxy, options map[string]any) (string, error) {
	return ProduceClashYAML(proxies, options)
}

// ProduceSurge outputs Surge-style [Proxy] entries.
func ProduceSurge(proxies []*model.Proxy, _ map[string]any) (string, error) {
	lines := []string{"[Proxy]"}
	for _, p := range proxies {
		if line := surgeLine(p); line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n"), nil
}

// ProduceSurgeMac outputs SurgeMac-style [Proxy] entries.
func ProduceSurgeMac(proxies []*model.Proxy, _ map[string]any) (string, error) {
	return ProduceSurge(proxies, nil)
}

func surgeLine(p *model.Proxy) string {
	name := p.GetString("name")
	if name == "" {
		name = p.Type()
	}
	name = strings.ReplaceAll(name, ",", "")
	base := fmt.Sprintf("%s = %s, %s, %d", name, p.Type(), p.Server(), p.Port())
	switch p.Type() {
	case "ss":
		if cipher := p.GetString("cipher"); cipher != "" {
			base += ", encrypt-method=" + cipher
		}
		base += ", password=" + p.GetString("password")
		if plugin := p.GetString("plugin"); plugin != "" {
			base += ", plugin=" + plugin
		}
		if opts := p.GetString("plugin-opts"); opts != "" {
			base += ", plugin-opts=" + opts
		}
	case "trojan":
		base += ", password=" + p.GetString("password")
		if p.GetBool("tls") {
			base += ", tls=true"
		}
		if sni := p.GetString("sni"); sni != "" {
			base += ", sni=" + sni
		}
	case "vmess":
		base += ", username=" + p.GetString("uuid")
		if p.GetString("network") == "ws" {
			base += ", ws=true, ws-path=" + p.GetString("ws-path")
			if h := p.GetString("ws-host"); h != "" {
				base += ", ws-headers=" + fmt.Sprintf("Host:%s", h)
			}
		}
		if p.GetBool("tls") {
			base += ", tls=true"
			if sni := p.GetString("sni"); sni != "" {
				base += ", sni=" + sni
			}
		}
	case "vless":
		base += ", username=" + p.GetString("uuid")
		if p.GetString("network") == "ws" {
			base += ", ws=true, ws-path=" + p.GetString("ws-path")
			if h := p.GetString("ws-host"); h != "" {
				base += ", ws-headers=" + fmt.Sprintf("Host:%s", h)
			}
		}
		if p.GetBool("tls") {
			base += ", tls=true"
			if sni := p.GetString("sni"); sni != "" {
				base += ", sni=" + sni
			}
		}
	case "hysteria2":
		base += ", password=" + p.GetString("password")
		if sni := p.GetString("sni"); sni != "" {
			base += ", sni=" + sni
		}
	case "hysteria":
		base += ", auth_str=" + p.GetString("auth-str")
		if sni := p.GetString("sni"); sni != "" {
			base += ", sni=" + sni
		}
	case "tuic":
		base += ", uuid=" + p.GetString("uuid")
		if sni := p.GetString("sni"); sni != "" {
			base += ", sni=" + sni
		}
	case "socks5", "socks":
		base += ", type=socks5"
		if u := p.GetString("username"); u != "" {
			base += ", username=" + u + ", password=" + p.GetString("password")
		}
	case "http", "https":
		base += ", type=" + p.Type()
		if u := p.GetString("username"); u != "" {
			base += ", username=" + u + ", password=" + p.GetString("password")
		}
	}
	if p.GetBool("udp") {
		base += ", udp-relay=true"
	}
	return base
}

// ProduceLoon outputs Loon [Proxy] entries.
func ProduceLoon(proxies []*model.Proxy, _ map[string]any) (string, error) {
	lines := []string{"[Proxy]"}
	for _, p := range proxies {
		if line := surgeLine(p); line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n"), nil
}
