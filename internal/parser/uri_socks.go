package parser

import (
	"fmt"
	"strings"

	"substore/internal/model"
)

func init() {
	MustRegister(
		&Parser{Name: "URI SOCKS Parser",
			Test: func(line string) bool {
				return strings.HasPrefix(line, "socks://")
			},
			Parse: func(line string) (*model.Proxy, error) {
				// socks://base64(user:pass)@host:port#name
				content, name := DecodeURIFragment(line)
				content = strings.TrimPrefix(content, "socks://")
				hostPort := content
				auth := ""
				if atIdx := strings.Index(content, "@"); atIdx != -1 {
					auth = content[:atIdx]
					hostPort = content[atIdx+1:]
				}
				host, port, ok := SplitHostPort(hostPort)
				if !ok || host == "" || port == "" {
					return nil, fmt.Errorf("invalid socks link")
				}
				p := model.NewProxy()
				p.Set("type", "socks5")
				p.Set("server", host)
				p.Set("port", port)
				if auth != "" {
					if d, err := Base64Decode(decodeURIComponent(auth)); err == nil {
						parts := strings.SplitN(d, ":", 2)
						if len(parts) == 2 {
							p.Set("username", parts[0])
							p.Set("password", parts[1])
						}
					}
				}
				if name != "" {
					p.Set("name", name)
				} else {
					p.Set("name", "Socks5 "+host+":"+port)
				}
				return p, nil
			},
		},
		&Parser{Name: "URI Proxy Parser",
			Test: func(line string) bool {
				return proxyURISchemeRe.MatchString(line)
			},
			Parse: func(line string) (*model.Proxy, error) {
				m := proxyURISchemeRe.FindStringSubmatch(line)
				if len(m) != 9 {
					return nil, fmt.Errorf("invalid proxy link")
				}
				typ := m[1]
				tls := m[2] != ""
				username := m[3]
				password := m[4]
				server := m[5]
				port := m[6]
				name := m[8]
				if port == "" {
					if tls {
						port = "443"
					} else if typ == "http" {
						port = "80"
					} else {
						return nil, fmt.Errorf("port not present in line")
					}
				}
				p := model.NewProxy()
				p.Set("type", typ)
				p.Set("tls", tls)
				p.Set("server", server)
				p.Set("port", port)
				if username != "" {
					p.Set("username", decodeURIComponent(username))
				}
				if password != "" {
					p.Set("password", decodeURIComponent(password))
				}
				if n := decodeURIComponent(name); n != "" {
					p.Set("name", n)
				} else {
					p.Set("name", typ+" "+server+":"+port)
				}
				return p, nil
			},
		},
	)
}

var proxyURISchemeRe = regexMust(`^(socks5\+tls|socks5|http|https)(\+tls)?:\/\/(?:(.*?):(.*?)@)?(.*?)(?::(\d+?))?\/?(\?.*?)?(?:#(.*?))?$`)
