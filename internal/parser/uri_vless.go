package parser

import (
	"fmt"
	"strings"

	"substore/internal/model"
)

func init() {
	MustRegister(&Parser{
		Name: "URI VLESS Parser",
		Test: func(line string) bool { return strings.HasPrefix(line, "vless://") },
		Parse: func(line string) (*model.Proxy, error) {
			return parseVless(strings.TrimPrefix(line, "vless://"))
		},
	})
}

func parseVless(payload string) (*model.Proxy, error) {
	content, name := DecodeURIFragment(payload)
	qIdx := strings.Index(content, "?")
	addrPart := content
	query := ""
	if qIdx != -1 {
		addrPart = content[:qIdx]
		query = content[qIdx+1:]
	}
	// uuid@host:port
	atIdx := strings.Index(addrPart, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid vless link")
	}
	uuid := addrPart[:atIdx]
	host, port, ok := SplitHostPort(addrPart[atIdx+1:])
	if !ok || host == "" || port == "" {
		return nil, fmt.Errorf("invalid vless server:port")
	}
	p := model.NewProxy()
	p.Set("type", "vless")
	p.Set("uuid", uuid)
	p.Set("server", host)
	p.Set("port", port)

	params := ParseURIParams(query)
	if params["encryption"] != "" && params["encryption"] != "none" {
		p.Set("encryption", params["encryption"])
	}
	security := params["security"]
	if security == "" {
		security = params["encryption"]
	}
	if security == "tls" || security == "reality" {
		p.Set("tls", true)
	}
	if params["sni"] != "" {
		p.Set("sni", params["sni"])
	}
	if params["fp"] != "" {
		p.Set("client-fingerprint", params["fp"])
	}
	if params["alpn"] != "" {
		p.Set("alpn", strings.Split(params["alpn"], ","))
	}
	if params["flow"] != "" && params["flow"] != "null" {
		p.Set("flow", params["flow"])
	}
	if params["allowInsecure"] == "1" || params["allowInsecure"] == "true" {
		p.Set("skip-cert-verify", true)
	}
	if params["pbk"] != "" {
		ropts := map[string]any{}
		ropts["public-key"] = params["pbk"]
		if params["sid"] != "" {
			ropts["short-id"] = params["sid"]
		}
		if params["spx"] != "" {
			ropts["spider-x"] = params["spx"]
		}
		p.Set("reality-opts", ropts)
	}
	// packet encoding
	if params["packetEncoding"] != "" {
		p.Set("packet-encoding", params["packetEncoding"])
	}

	// transport
	network := params["type"]
	if network != "" {
		p.Set("network", network)
		opts := map[string]any{}
		path := params["path"]
		hostHeader := params["host"]
		switch network {
		case "ws", "http", "h2", "httpupgrade":
			if network == "httpupgrade" {
				network = "ws"
				opts["v2ray-http-upgrade"] = true
			}
			if path != "" {
				opts["path"] = path
			} else if network == "ws" || network == "h2" {
				opts["path"] = "/"
			}
			if network == "h2" {
				if hostHeader != "" {
					opts["host"] = []any{hostHeader}
				}
			} else if hostHeader != "" {
				opts["headers"] = map[string]any{"Host": hostHeader}
			}
			if hostHeader == "" && !isIPString(host) {
				opts["headers"] = map[string]any{"Host": host}
			}
			p.Set(network+"-opts", opts)
		case "grpc":
			opts["grpc-service-name"] = path
			if params["serviceName"] != "" {
				opts["grpc-service-name"] = params["serviceName"]
			}
			p.Set("grpc-opts", opts)
		case "kcp", "quic":
			opts["path"] = path
			p.Set(network+"-opts", opts)
		}
	}

	if name != "" {
		p.Set("name", name)
	} else {
		p.Set("name", "VLESS "+host+":"+port)
	}
	return p, nil
}

func init() {
	MustRegister(&Parser{
		Name: "URI Trojan Parser",
		Test: func(line string) bool { return strings.HasPrefix(line, "trojan://") },
		Parse: func(line string) (*model.Proxy, error) {
			return parseTrojan(strings.TrimPrefix(line, "trojan://"))
		},
	})
}

func parseTrojan(payload string) (*model.Proxy, error) {
	content, name := DecodeURIFragment(payload)
	password := ""
	addrPart := content
	if atIdx := strings.Index(content, "@"); atIdx != -1 {
		password = content[:atIdx]
		addrPart = content[atIdx+1:]
	}
	qIdx := strings.Index(addrPart, "?")
	query := ""
	if qIdx != -1 {
		query = addrPart[qIdx+1:]
		addrPart = addrPart[:qIdx]
	}
	host, port, ok := SplitHostPort(addrPart)
	if !ok || host == "" || port == "" {
		return nil, fmt.Errorf("invalid trojan server:port")
	}
	p := model.NewProxy()
	p.Set("type", "trojan")
	p.Set("server", host)
	p.Set("port", port)
	p.Set("password", password)
	p.Set("tls", true)

	params := ParseURIParams(query)
	if params["sni"] != "" {
		p.Set("sni", params["sni"])
	}
	if params["peer"] != "" && !p.Has("sni") {
		p.Set("sni", params["peer"])
	}
	if params["allowInsecure"] == "1" || params["allowInsecure"] == "true" {
		p.Set("skip-cert-verify", true)
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
	if params["type"] == "ws" {
		p.Set("network", "ws")
		opts := map[string]any{"path": "/"}
		if params["path"] != "" {
			opts["path"] = params["path"]
		}
		if params["host"] != "" {
			opts["headers"] = map[string]any{"Host": params["host"]}
		} else if !isIPString(host) {
			opts["headers"] = map[string]any{"Host": host}
		}
		p.Set("ws-opts", opts)
	} else if params["type"] == "grpc" {
		p.Set("network", "grpc")
		p.Set("grpc-opts", map[string]any{"grpc-service-name": params["serviceName"]})
	}
	if name != "" {
		p.Set("name", name)
	} else {
		p.Set("name", "Trojan "+host+":"+port)
	}
	return p, nil
}
