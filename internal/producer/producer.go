package producer

import (
	"fmt"
	"sort"
	"strings"

	"substore/internal/model"
)

// Producer converts a list of proxies into a target format string.
type Producer func(proxies []*model.Proxy, options map[string]any) (string, error)

// Registry maps target names to producers.
type Registry map[string]Producer

var registry = Registry{}

func init() {
	registry["json"] = ProduceJSON
	registry["uri"] = ProduceURI
	registry["clash"] = ProduceClashYAML
	registry["mihomo"] = ProduceClashYAML
	registry["stash"] = ProduceClashYAML
	registry["surge"] = ProduceSurge
	registry["surge-mac"] = ProduceSurgeMac
	registry["surfboard"] = ProduceSurge
	registry["loon"] = ProduceLoon
	registry["shadowrocket"] = ProduceURI
	registry["qx"] = ProduceQX
	registry["sing-box"] = ProduceSingBox
	registry["v2ray"] = ProduceV2Ray
	registry["egern"] = ProduceSurge
}

// Get returns a producer by target name.
func Get(name string) (Producer, bool) {
	p, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	return p, ok
}

// Known reports whether a target is supported.
func Known(name string) bool {
	_, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// Names returns sorted supported target names.
func Names() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func joinNonEmpty(lines []string) string {
	parts := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			parts = append(parts, l)
		}
	}
	return strings.Join(parts, "\n")
}

func errUnsupported(target string) error {
	return fmt.Errorf("unsupported target: %s", target)
}
