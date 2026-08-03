package parser

import (
	"fmt"
	"regexp"
	"strconv"
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

var tuicRe = regexp.MustCompile(`^(.*?)@(.*?)(?::(\d+))?/?(?:\?(.*?))?(?:#(.*?))?$`)

func parseTuic(payload string) (*model.Proxy, error) {
	m := tuicRe.FindStringSubmatch(payload)
	if m == nil || m[1] == "" || m[2] == "" {
		return nil, fmt.Errorf("invalid tuic link")
	}
	auth := decodeURIComponent(m[1])
	server := m[2]
	port := m[3]
	addons := m[4]
	name := m[5]

	if port == "" {
		port = "443"
	}
	uuid, password := splitFirstColon(auth)
	password = decodeURIComponent(password)

	p := model.NewProxy()
	p.Set("type", "tuic")
	p.Set("server", server)
	p.Set("port", port)
	p.Set("password", password)
	p.Set("uuid", uuid)

	for _, addon := range strings.Split(addons, "&") {
		if addon == "" {
			continue
		}
		kv := strings.SplitN(addon, "=", 2)
		key := strings.ReplaceAll(kv[0], "_", "-")
		val := ""
		if len(kv) == 2 {
			val = decodeURIComponent(kv[1])
		}
		switch {
		case key == "alpn":
			if val != "" {
				p.Set("alpn", strings.Split(val, ","))
			}
		case key == "allow-insecure" || key == "insecure":
			p.Set("skip-cert-verify", trueBool(val))
		case key == "fast-open":
			p.Set("tfo", true)
		case key == "disable-sni" || key == "reduce-rtt":
			p.Set(key, trueBool(val))
		case key == "congestion-control":
			p.Set("congestion-controller", val)
		default:
			if !p.Has(key) {
				p.Set(key, val)
			}
		}
	}
	if name != "" {
		p.Set("name", decodeURIComponent(name))
	} else {
		p.Set("name", "TUIC "+server+":"+port)
	}
	return p, nil
}

var anytlsRe = regexp.MustCompile(`^(.*?)@(.*?)(?::(\d+))?/?(?:\?(.*?))?(?:#(.*?))?$`)

// parseAnyTLS mirrors Sub-Store URI_AnyTLS: the URI is parsed through the
// VLESS parser and the transport metadata is kept (except "tcp" without
// reality opts), with the anytls password/server/port fields applied last.
func parseAnyTLS(payload string) (*model.Proxy, error) {
	content, name := DecodeURIFragment(payload)
	m := anytlsRe.FindStringSubmatch(content)
	if m == nil || m[1] == "" || m[2] == "" {
		return nil, fmt.Errorf("invalid anytls link")
	}
	password := decodeURIComponent(decodeURIComponent(m[1]))
	server := m[2]
	port := m[3]
	addons := m[4]
	if port == "" {
		port = "443"
	}

	p := model.NewProxy()
	p.Set("type", "anytls")
	p.Set("server", server)
	p.Set("port", port)
	p.Set("password", password)

	for _, addon := range strings.Split(addons, "&") {
		if addon == "" {
			continue
		}
		kv := strings.SplitN(addon, "=", 2)
		key := strings.ReplaceAll(kv[0], "_", "-")
		val := ""
		if len(kv) == 2 {
			val = decodeURIComponent(kv[1])
		}
		switch {
		case key == "alpn":
			if val != "" {
				p.Set("alpn", strings.Split(val, ","))
			}
		case key == "insecure":
			p.Set("skip-cert-verify", trueBool(val))
		case key == "udp":
			p.Set("udp", trueBool(val))
		default:
			if !p.Has(key) {
				p.Set(key, val)
			}
		}
	}

	if p.GetString("network") == "tcp" && !p.Has("reality-opts") {
		p.Delete("network")
		p.Delete("security")
	}

	if name != "" {
		p.Set("name", name)
	} else {
		p.Set("name", "AnyTLS "+server+":"+port)
	}
	return p, nil
}

var wgRe = regexp.MustCompile(`^((.*?)@)?(.*?)(:(\d+))?/?(?:\?(.*?))?(?:#(.*?))?$`)

func parseWireGuard(payload string) (*model.Proxy, error) {
	// the line may contain a #fragment which must survive in the name
	line := payload
	nameRaw := ""
	if idx := strings.Index(line, "#"); idx != -1 {
		nameRaw = line[idx+1:]
		line = line[:idx]
	}
	m := wgRe.FindStringSubmatch(line)
	if m == nil || m[3] == "" {
		return nil, fmt.Errorf("invalid wireguard link")
	}
	privateKey := ""
	if m[2] != "" {
		privateKey = decodeURIComponent(m[2])
	}
	server := m[3]
	port := m[5]
	addons := m[6]

	if port == "" {
		port = "51820"
	}
	name := "WireGuard " + server + ":" + port
	if nameRaw != "" {
		name = decodeURIComponent(nameRaw)
	}

	p := model.NewProxy()
	p.Set("type", "wireguard")
	p.Set("name", name)
	p.Set("server", server)
	p.Set("port", port)
	p.Set("private-key", privateKey)
	p.Set("udp", true)

	for _, addon := range strings.Split(addons, "&") {
		if addon == "" {
			continue
		}
		equalIndex := strings.Index(addon, "=")
		key := addon
		val := ""
		if equalIndex != -1 {
			key = addon[:equalIndex]
			val = decodeURIComponent(addon[equalIndex+1:])
		}
		key = strings.Replace(key, "_", "-", 1)
		switch {
		case key == "reserved":
			parsed := []any{}
			for _, item := range strings.Split(val, ",") {
				if n, err := strconv.Atoi(strings.TrimSpace(item)); err == nil {
					parsed = append(parsed, n)
				}
			}
			if len(parsed) == 3 {
				p.Set("reserved", parsed)
			}
		case key == "address" || key == "ip":
			for _, item := range strings.Split(val, ",") {
				addr, ok := parseWireGuardURIAddressValue(item)
				if !ok {
					continue
				}
				if addr.family == "ipv4" {
					p.Set("ip", addr.address)
					if addr.cidr >= 0 {
						p.Set("ip-cidr", addr.cidr)
					}
				} else {
					p.Set("ipv6", addr.address)
					if addr.cidr >= 0 {
						p.Set("ipv6-cidr", addr.cidr)
					}
				}
			}
		case key == "mtu":
			if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
				p.Set("mtu", n)
			}
		case regexp.MustCompile(`(?i)publickey`).MatchString(key):
			p.Set("public-key", val)
		case regexp.MustCompile(`(?i)privatekey`).MatchString(key):
			p.Set("private-key", val)
		case key == "udp":
			p.Set("udp", trueBool(val))
		default:
			if !p.Has(key) && key != "flag" {
				p.Set(key, val)
			}
		}
	}
	return p, nil
}

type wgAddress struct {
	family  string
	address string
	cidr    int
}

func parseWireGuardURIAddressValue(value string) (wgAddress, bool) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return wgAddress{}, false
	}
	m := wgAddressRe.FindStringSubmatch(raw)
	hostRaw := raw
	cidrRaw := ""
	if m != nil {
		if m[1] != "" {
			hostRaw = m[1]
		}
		cidrRaw = m[2]
	}
	host := strings.Trim(strings.Trim(strings.TrimSpace(hostRaw), "]"), "[")
	cidr := -1
	if cidrRaw != "" {
		if regexp.MustCompile(`^\d+$`).MatchString(cidrRaw) {
			if n, err := strconv.Atoi(cidrRaw); err == nil {
				cidr = n
			}
		}
	}
	if isIPv4String(host) {
		if cidr > 32 {
			cidr = -1
		}
		return wgAddress{"ipv4", host, cidr}, true
	}
	if isIPv6String(host) {
		if cidr > 128 {
			cidr = -1
		}
		return wgAddress{"ipv6", host, cidr}, true
	}
	return wgAddress{}, false
}

var wgAddressRe = regexp.MustCompile(`^(.*?)(?:/(\d+))?$`)

func splitFirstColon(s string) (string, string) {
	idx := strings.Index(s, ":")
	if idx == -1 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}
