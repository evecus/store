package producer

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"substore/internal/model"
)

// ProduceJSON outputs each proxy as a JSON line.
func ProduceJSON(proxies []*model.Proxy, _ map[string]any) (string, error) {
	lines := make([]string, 0, len(proxies))
	for _, p := range proxies {
		b, err := json.Marshal(p.Data())
		if err != nil {
			return "", err
		}
		lines = append(lines, string(b))
	}
	return strings.Join(lines, "\n"), nil
}

// ProduceURI outputs each proxy in its URI format.
func ProduceURI(proxies []*model.Proxy, _ map[string]any) (string, error) {
	lines := make([]string, 0, len(proxies))
	for _, p := range proxies {
		if uri := ToURI(p); uri != "" {
			lines = append(lines, uri)
		}
	}
	return strings.Join(lines, "\n"), nil
}

// ToURI converts a proxy to its URI representation.
func ToURI(p *model.Proxy) string {
	switch p.Type() {
	case "ss":
		payload := p.GetString("cipher") + ":" + p.GetString("password") + "@" + p.Server() + ":" + fmt.Sprint(p.Port())
		u := "ss://" + b64Std(payload)
		q := url.Values{}
		if name := p.GetString("name"); name != "" {
			q.Set("name", name)
		}
		if plugin := p.GetString("plugin"); plugin != "" {
			opts := p.GetString("plugin-opts")
			q.Set("plugin", plugin+(optSep(opts))+opts)
		}
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		return u
	case "ssr":
		return ssrURI(p)
	case "vmess":
		return vmessURI(p)
	case "vless":
		return vlessURI(p)
	case "trojan":
		return trojanURI(p)
	case "hysteria":
		return hysteriaURI(p)
	case "hysteria2":
		return hysteria2URI(p)
	case "tuic":
		return tuicURI(p)
	case "wireguard":
		return wireguardURI(p)
	case "anytls":
		return anytlsURI(p)
	case "socks5", "socks", "http", "https":
		return httpSocksURI(p)
	default:
		return ""
	}
}

func optSep(opts string) string {
	if opts == "" {
		return ""
	}
	return ";"
}

func b64Std(s string) string {
	return base64StdEncode([]byte(s))
}

func b64URL(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(base64StdEncode([]byte(s)), "+", "-"), "/", "_")
}

func httpSocksURI(p *model.Proxy) string {
	scheme := p.Type()
	if scheme == "socks" {
		scheme = "socks5"
	}
	auth := ""
	if p.GetString("username") != "" {
		auth = url.QueryEscape(p.GetString("username")) + ":" + url.QueryEscape(p.GetString("password")) + "@"
	}
	u := scheme + "://" + auth + p.Server() + ":" + fmt.Sprint(p.Port())
	if p.GetString("name") != "" {
		u += "#" + url.QueryEscape(p.GetString("name"))
	}
	return u
}

func ssrURI(p *model.Proxy) string {
	params := fmt.Sprintf("obfsparam=%s&protoparam=%s&remarks=%s&group=%s",
		b64URL(p.GetString("obfs-param")),
		b64URL(p.GetString("proto-param")),
		b64URL(p.GetString("name")),
		b64URL(p.GetString("group")))
	payload := b64URL(fmt.Sprintf("%s:%s:%s:%s:%s:%s/?%s",
		p.Server(), fmt.Sprint(p.Port()),
		p.GetString("proto"), p.GetString("cipher"),
		p.GetString("obfs"), p.GetString("password"), params))
	return "ssr://" + payload
}

func vmessURI(p *model.Proxy) string {
	payload := p.Data()
	delete(payload, "name")
	b, _ := json.Marshal(payload)
	return "vmess://" + b64URL(string(b))
}

func vlessURI(p *model.Proxy) string {
	u := &url.URL{Scheme: "vless", Host: p.Server() + ":" + fmt.Sprint(p.Port()), User: url.User(p.GetString("username"))}
	q := url.Values{}
	q.Set("type", p.GetString("network"))
	switch p.GetString("network") {
	case "ws":
		q.Set("path", p.GetString("ws-path"))
		q.Set("host", p.GetString("ws-host"))
	case "grpc":
		q.Set("serviceName", p.GetString("grpc-service-name"))
	}
	if p.GetBool("tls") {
		q.Set("security", "tls")
		q.Set("sni", p.GetString("sni"))
	} else if p.GetBool("reality") {
		q.Set("security", "reality")
		q.Set("sni", p.GetString("sni"))
		q.Set("pbk", p.GetString("pbk"))
		q.Set("fp", p.GetString("fp"))
		q.Set("sid", p.GetString("sid"))
		q.Set("spx", p.GetString("spx"))
	}
	if p.GetBool("skip-cert-verify") {
		q.Set("allowInsecure", "1")
	}
	u.RawQuery = q.Encode()
	if name := p.GetString("name"); name != "" {
		return u.String() + "#" + url.QueryEscape(name)
	}
	return u.String()
}

func trojanURI(p *model.Proxy) string {
	u := &url.URL{Scheme: "trojan", Host: p.Server() + ":" + fmt.Sprint(p.Port()), User: url.User(p.GetString("password"))}
	q := url.Values{}
	if p.GetString("network") == "ws" {
		q.Set("type", "ws")
		q.Set("path", p.GetString("ws-path"))
		q.Set("host", p.GetString("ws-host"))
	}
	q.Set("sni", p.GetString("sni"))
	if p.GetBool("skip-cert-verify") {
		q.Set("allowInsecure", "1")
	}
	u.RawQuery = q.Encode()
	if name := p.GetString("name"); name != "" {
		return u.String() + "#" + url.QueryEscape(name)
	}
	return u.String()
}

func hysteriaURI(p *model.Proxy) string {
	u := &url.URL{Scheme: "hysteria", Host: p.Server() + ":" + fmt.Sprint(p.Port())}
	q := url.Values{}
	q.Set("protocol", p.GetString("protocol"))
	q.Set("up", fmt.Sprint(p.GetString("up-mbps")))
	q.Set("down", fmt.Sprint(p.GetString("down-mbps")))
	q.Set("alpn", p.GetString("alpn"))
	q.Set("peer", p.GetString("sni"))
	if p.GetBool("skip-cert-verify") {
		q.Set("insecure", "1")
	}
	if p.GetBool("obfs") {
		q.Set("obfs", p.GetString("obfs-password"))
	}
	u.RawQuery = q.Encode()
	if name := p.GetString("name"); name != "" {
		return u.String() + "#" + url.QueryEscape(name)
	}
	return u.String()
}

func hysteria2URI(p *model.Proxy) string {
	u := &url.URL{Scheme: "hysteria2", Host: p.Server() + ":" + fmt.Sprint(p.Port()), User: url.User(p.GetString("password"))}
	q := url.Values{}
	q.Set("sni", p.GetString("sni"))
	if p.GetString("alpn") != "" {
		q.Set("alpn", p.GetString("alpn"))
	}
	if p.GetBool("skip-cert-verify") {
		q.Set("insecure", "1")
	}
	if p.GetBool("obfs") {
		q.Set("obfs", p.GetString("obfs-type"))
		q.Set("obfs-password", p.GetString("obfs-password"))
	}
	u.RawQuery = q.Encode()
	if name := p.GetString("name"); name != "" {
		return u.String() + "#" + url.QueryEscape(name)
	}
	return u.String()
}

func tuicURI(p *model.Proxy) string {
	u := &url.URL{Scheme: "tuic", Host: p.Server() + ":" + fmt.Sprint(p.Port()), User: url.User(p.GetString("uuid"))}
	q := url.Values{}
	q.Set("sni", p.GetString("sni"))
	q.Set("alpn", p.GetString("alpn"))
	if p.GetString("congestion-control") != "" {
		q.Set("congestion-control", p.GetString("congestion-control"))
	}
	if p.GetBool("skip-cert-verify") {
		q.Set("allow_insecure", "1")
	}
	u.RawQuery = q.Encode()
	if name := p.GetString("name"); name != "" {
		return u.String() + "#" + url.QueryEscape(name)
	}
	return u.String()
}

func wireguardURI(p *model.Proxy) string {
	base := fmt.Sprintf("wireguard://%s:%d?publicKey=%s&privateKey=%s&ip=%s",
		p.Server(), p.Port(), url.QueryEscape(p.GetString("public-key")),
		url.QueryEscape(p.GetString("private-key")), url.QueryEscape(p.GetString("ip")))
	if mtu := p.GetInt("mtu"); mtu > 0 {
		base += fmt.Sprintf("&mtu=%d", mtu)
	}
	if udp := p.GetString("udp-port"); udp != "" {
		base += "&udpPort=" + udp
	}
	if name := p.GetString("name"); name != "" {
		base += "#" + url.QueryEscape(name)
	}
	return base
}

func anytlsURI(p *model.Proxy) string {
	u := &url.URL{Scheme: "anytls", Host: p.Server() + ":" + fmt.Sprint(p.Port()), User: url.User(p.GetString("password"))}
	q := url.Values{}
	q.Set("sni", p.GetString("sni"))
	if p.GetBool("skip-cert-verify") {
		q.Set("insecure", "1")
	}
	u.RawQuery = q.Encode()
	if name := p.GetString("name"); name != "" {
		return u.String() + "#" + url.QueryEscape(name)
	}
	return u.String()
}
