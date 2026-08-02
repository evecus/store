package parser

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"substore/internal/model"
)

func init() {
	MustRegister(&Parser{
		Name: "URI VMess Parser",
		Test: func(line string) bool { return strings.HasPrefix(line, "vmess://") },
		Parse: func(line string) (*model.Proxy, error) {
			return parseVMess(strings.TrimPrefix(line, "vmess://"))
		},
	})
}

func parseVMess(payload string) (*model.Proxy, error) {
	content, fragmentName := DecodeURIFragment(payload)
	// strip query
	base := content
	if qIdx := strings.Index(base, "?"); qIdx != -1 {
		base = base[:qIdx]
	}
	decoded, err := Base64Decode(base)
	if err != nil {
		return nil, err
	}

	// Quantumult X vmess format: name=vmess,server,port,method,uuid...
	if strings.Contains(decoded, "=vmess") {
		return parseVmessQX(decoded, fragmentName)
	}

	// Try v2rayN JSON
	var params map[string]any
	if err := json.Unmarshal([]byte(decoded), &params); err == nil {
		return parseVmessJSON(params, fragmentName)
	}

	// Shadowrocket format: method:uuid@server:port?query
	return parseVmessShadowrocket(decoded, fragmentName)
}

func parseVmessQX(decoded, fragmentName string) (*model.Proxy, error) {
	partitions := strings.Split(decoded, ",")
	// partition[0] = name=vmess
	name := strings.TrimSuffix(strings.SplitN(partitions[0], "=", 2)[0], "=")
	params := map[string]string{}
	for _, part := range partitions {
		if idx := strings.Index(part, "="); idx != -1 {
			params[strings.TrimSpace(part[:idx])] = strings.TrimSpace(part[idx+1:])
		}
	}
	p := model.NewProxy()
	p.Set("type", "vmess")
	p.Set("name", name)
	if len(partitions) > 1 {
		p.Set("server", strings.TrimSpace(partitions[1]))
	}
	if len(partitions) > 2 {
		p.Set("port", strings.TrimSpace(partitions[2]))
	}
	if len(partitions) > 3 {
		p.Set("cipher", strings.ToLower(strings.TrimSpace(partitions[3])))
	}
	if len(partitions) > 4 {
		uuid := strings.TrimSpace(partitions[4])
		uuid = strings.Trim(uuid, "\"")
		p.Set("uuid", uuid)
	}
	if params["obfs"] == "wss" {
		p.Set("tls", true)
	}
	if params["udp-relay"] != "" {
		p.Set("udp", true)
	}
	if params["fast-open"] != "" {
		p.Set("tfo", true)
	}
	if params["tls-verification"] != "" {
		p.Set("skip-cert-verify", !isTrue(params["tls-verification"]))
	}
	if obfs := params["obfs"]; obfs == "ws" || obfs == "wss" {
		p.Set("network", "ws")
		opts := map[string]any{}
		path := params["obfs-path"]
		if path == "" {
			path = "/"
		}
		path = strings.Trim(path, "\"")
		opts["path"] = path
		if h := params["obfs-header"]; h != "" {
			if idx := strings.Index(h, "Host:"); idx != -1 {
				hostField := h[idx+5:]
				hostField = strings.TrimSpace(hostField)
				if sp := strings.Index(hostField, "\r\n"); sp != -1 {
					hostField = hostField[:sp]
				}
				if sp := strings.Index(hostField, "\n"); sp != -1 {
					hostField = hostField[:sp]
				}
				hostField = strings.Trim(hostField, "\"")
				opts["headers"] = map[string]any{"Host": hostField}
			}
		}
		p.Set("ws-opts", opts)
	}
	if fragmentName != "" {
		p.Set("name", fragmentName)
	}
	return p, nil
}

func parseVmessJSON(params map[string]any, fragmentName string) (*model.Proxy, error) {
	server := getString(params, "add")
	portStr := fmt.Sprint(params["port"])
	if v, ok := params["port"].(float64); ok {
		portStr = strconv.Itoa(int(v))
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 0
	}
	p := model.NewProxy()
	p.Set("type", "vmess")
	p.Set("server", server)
	p.Set("port", port)
	p.Set("uuid", getString(params, "id"))
	cipher := getString(params, "scy")
	if cipher == "" {
		cipher = getString(params, "security")
	}
	p.Set("cipher", strings.ToLower(cipher))
	p.Set("alterId", int(toFloat(params["aid"])))
	name := getString(params, "ps")
	if name == "" {
		name = getString(params, "remarks")
	}
	if name == "" {
		name = getString(params, "remark")
	}
	if name == "" {
		name = "VMess " + server + ":" + portStr
	}
	p.Set("name", name)
	tls := getString(params, "tls")
	p.Set("tls", tls == "tls" || tls == "1" || tls == "true")
	if getString(params, "sni") != "" {
		p.Set("sni", getString(params, "sni"))
	} else if getString(params, "peer") != "" {
		p.Set("sni", getString(params, "peer"))
	}
	if getString(params, "fp") != "" {
		p.Set("client-fingerprint", getString(params, "fp"))
	}
	if getString(params, "alpn") != "" {
		p.Set("alpn", strings.Split(getString(params, "alpn"), ","))
	}

	// transport
	netw := getString(params, "net")
	if getString(params, "obfs") == "websocket" {
		netw = "ws"
	}
	if getString(params, "type") == "http" || getString(params, "obfs") == "http" {
		netw = "http"
	}
	if netw == "httpupgrade" {
		netw = "ws"
	}
	switch netw {
	case "ws":
		p.Set("network", "ws")
		opts := map[string]any{}
		path := getString(params, "path")
		if path == "" {
			path = "/"
		}
		opts["path"] = path
		if host := getString(params, "host"); host != "" {
			opts["headers"] = map[string]any{"Host": host}
		}
		p.Set("ws-opts", opts)
	case "http", "h2":
		p.Set("network", "http")
		opts := map[string]any{}
		if path := getString(params, "path"); path != "" {
			opts["path"] = path
		} else {
			opts["path"] = "/"
		}
		if host := getString(params, "host"); host != "" {
			opts["headers"] = map[string]any{"Host": host}
		}
		p.Set("http-opts", opts)
	case "grpc":
		p.Set("network", "grpc")
		opts := map[string]any{"grpc-service-name": getString(params, "path")}
		p.Set("grpc-opts", opts)
	case "tcp":
		// keep tcp network; some fields may exist
		p.Set("network", "tcp")
	}

	// tls verification
	if p.GetBool("tls") && getString(params, "verify_cert") != "" {
		p.Set("skip-cert-verify", !isTrue(getString(params, "verify_cert")))
	}
	if getString(params, "allowInsecure") != "" {
		p.Set("skip-cert-verify", isTrue(getString(params, "allowInsecure")))
	}

	if fragmentName != "" {
		p.Set("name", fragmentName)
	}
	return p, nil
}

func parseVmessShadowrocket(decoded, fragmentName string) (*model.Proxy, error) {
	re := regexp.MustCompile(`^[^:]+?:[^:]+?@(.*):(\d+)$`)
	m := re.FindStringSubmatch(decoded)
	if len(m) != 3 {
		return nil, fmt.Errorf("invalid vmess shadowrocket link")
	}
	cipher, uuid, server, port := "", "", m[1], m[2]
	// split method:uuid
	head := strings.SplitN(decoded, "@", 2)[0]
	cu := strings.SplitN(head, ":", 2)
	if len(cu) == 2 {
		cipher, uuid = cu[0], cu[1]
	}
	p := model.NewProxy()
	p.Set("type", "vmess")
	p.Set("server", server)
	p.Set("port", port)
	p.Set("uuid", uuid)
	p.Set("cipher", strings.ToLower(cipher))
	p.Set("name", "VMess "+server+":"+port)
	if fragmentName != "" {
		p.Set("name", fragmentName)
	}
	return p, nil
}

func toFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	default:
		return 0
	}
}

func isTrue(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "1" || s == "true" || s == "yes" || s == "on"
}
