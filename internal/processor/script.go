package processor

import (
	"context"
	"math/rand"
	"net/netip"
	"time"

	"substore/internal/model"
)

func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	return rand.Intn(n)
}

func scriptFilter(_ any, _ *Context) Processor {
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		// Script filtering is not supported; the filter is a no-op.
		return proxies, nil
	}
}

func scriptOperator(_ any, _ *Context) Processor {
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		// Script operators are not supported; the operator is a no-op.
		return proxies, nil
	}
}

func resolveDomainOperator(args any) Processor {
	m := toMap(args)
	format := fmt_str(m["format"])
	if format == "" {
		format = "host"
	}
	resolver := newDNSResolver()
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		for _, p := range proxies {
			if _, err := netip.ParseAddr(p.Server()); err == nil {
				continue // already an IP
			}
			ips, err := resolver.resolve(p.Server())
			if err != nil || len(ips) == 0 {
				continue
			}
			switch format {
			case "full":
				p.Set("server", p.Server()+":"+ips[0])
			case "only":
				p.Set("server", ips[0])
			default:
				p.Set("server", ips[0])
			}
		}
		return proxies, nil
	}
}

func fmt_str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

type dnsResolver struct {
	cache map[string][]string
}

func newDNSResolver() *dnsResolver {
	return &dnsResolver{cache: map[string][]string{}}
}

func (r *dnsResolver) resolve(host string) ([]string, error) {
	if ips, ok := r.cache[host]; ok {
		return ips, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Plain Go resolver is used (no custom DoH) to keep the binary self-contained.
	ips, err := netLookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	r.cache[host] = ips
	return ips, nil
}
