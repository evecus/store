package parser

import (
	"encoding/json"
	"strings"

	"gopkg.in/yaml.v3"

	"substore/internal/model"
)

func init() {
	MustRegister(
		&Parser{Name: "Clash Proxy Parser",
			Test: func(line string) bool {
				return strings.HasPrefix(line, "{") || strings.HasPrefix(line, "- {")
			},
			Parse: parseClashLine,
		},
	)
}

// parseClashLine parses a single Clash proxy definition given as inline JSON
// or inline YAML map.
func parseClashLine(line string) (*model.Proxy, error) {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "-")
	line = strings.TrimSpace(line)

	var fields map[string]any
	if strings.HasPrefix(line, "{") {
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			if err := yaml.Unmarshal([]byte(line), &fields); err != nil {
				return nil, err
			}
		}
	} else {
		if err := yaml.Unmarshal([]byte(line), &fields); err != nil {
			return nil, err
		}
	}
	if fields == nil {
		return nil, errInvalidJSON
	}
	typ, _ := fields["type"].(string)
	if typ == "" {
		return nil, errInvalidJSON
	}
	p := model.NewProxy()
	p.Set("type", typ)
	for k, v := range fields {
		switch k {
		case "udp":
			p.Set("udp", toBool(v))
		case "tfo", "fast-open":
			p.Set("tfo", toBool(v))
		case "skip-cert-verify", "allow-insecure":
			p.Set("skip-cert-verify", toBool(v))
		case "port", "port-range":
			p.Set(k, toInt(v))
		case "tls":
			p.Set("tls", toBool(v))
		default:
			p.Set(k, v)
		}
	}
	if p.GetString("name") == "" {
		p.Set("name", typ+" "+p.Server())
	}
	return p, nil
}

func toBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return isTrue(t)
	case int:
		return t != 0
	case float64:
		return t != 0
	default:
		return false
	}
}

func toInt(v any) int {
	return int(toFloat(v))
}
