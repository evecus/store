package processor

import (
	"context"
	"net"
)

func netLookupHost(ctx context.Context, host string) ([]string, error) {
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}
