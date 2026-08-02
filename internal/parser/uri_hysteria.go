package parser

import (
	"fmt"
	"strings"

	"substore/internal/model"
)

func init() {
	MustRegister(
		&Parser{Name: "URI Hysteria Parser",
			Test: func(line string) bool {
				return strings.HasPrefix(line, "hysteria://")
			},
			Parse: func(line string) (*model.Proxy, error) {
				return parseHysteria(strings.TrimPrefix(line, "hysteria://"))
			},
		},
		&Parser{Name: "URI Hysteria2 Parser",
			Test: func(line string) bool {
				return strings.HasPrefix(line, "hysteria2://") || strings.HasPrefix(line, "hy2://")
			},
			Parse: func(line string) (*model.Proxy, error) {
				payload := strings.TrimPrefix(line, "hysteria2://")
				payload = strings.TrimPrefix(payload, "hy2://")
				return parseHysteria2(payload)
			},
		},
	)
}

func parseHysteria(payload string) (*model.Proxy, error) {
	content, name := DecodeURIFragment(payload)
	qIdx := strings.Index(content, "?")
	addrPart := content
	query := ""
	if qIdx != -1 {
		addrPart = content[:qIdx]
		query = content[qIdx+1:]
	}
	host, port, ok := SplitHostPort(addrPart)
	if !ok || host == "" || port == "" {
		return nil, fmt.Errorf("invalid hysteria server:port")
	}
	p := model.NewProxy()
	p.Set("type", "hysteria")
	p.Set("server", host)
	p.Set("port", port)
	params := ParseURIParams(query)
	up := params["up"]
	if up == "" {
		up = params["upmbps"]
	}
	down := params["down"]
	if down == "" {
		down = params["downmbps"]
	}
	if up != "" {
		p.Set("up", up)
	}
	if down != "" {
		p.Set("down", down)
	}
	if params["auth"] != "" {
		p.Set("auth", params["auth"])
	}
	if params["obfs"] != "" {
		p.Set("obfs", params["obfs"])
	}
	if params["protocol"] != "" {
		p.Set("protocol", params["protocol"])
	}
	if params["insecure"] == "1" || params["insecure"] == "true" {
		p.Set("skip-cert-verify", true)
	}
	if params["sni"] != "" {
		p.Set("sni", params["sni"])
	}
	if params["alpn"] != "" {
		p.Set("alpn", strings.Split(params["alpn"], ","))
	}
	if name != "" {
		p.Set("name", name)
	} else {
		p.Set("name", "Hysteria "+host+":"+port)
	}
	return p, nil
}

func parseHysteria2(payload string) (*model.Proxy, error) {
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
		return nil, fmt.Errorf("invalid hysteria2 server:port")
	}
	p := model.NewProxy()
	p.Set("type", "hysteria2")
	p.Set("server", host)
	p.Set("port", port)
	if password != "" {
		p.Set("password", password)
	}
	params := ParseURIParams(query)
	if params["sni"] != "" {
		p.Set("sni", params["sni"])
	}
	if params["peer"] != "" && !p.Has("sni") {
		p.Set("sni", params["peer"])
	}
	if params["insecure"] == "1" || params["insecure"] == "true" {
		p.Set("skip-cert-verify", true)
	}
	if params["obfs"] != "" {
		p.Set("obfs", params["obfs"])
	}
	if params["obfs-password"] != "" {
		p.Set("obfs-password", params["obfs-password"])
	}
	if params["alpn"] != "" {
		p.Set("alpn", strings.Split(params["alpn"], ","))
	}
	if params["fp"] != "" {
		p.Set("client-fingerprint", params["fp"])
	}
	if params["pinSHA256"] != "" {
		p.Set("pin-sha256", params["pinSHA256"])
	}
	if name != "" {
		p.Set("name", name)
	} else {
		p.Set("name", "Hysteria2 "+host+":"+port)
	}
	return p, nil
}
