package share

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"substore/internal/downloader"
	"substore/internal/model"
	"substore/internal/pipeline"
	"substore/internal/store"
)

// Resolver resolves shared download requests for tokens.
type Resolver struct {
	Store *store.Store
	Fetch func(ctx context.Context, sub model.Sub) (string, error)
}

// NewResolver creates a resolver backed by the given store.
func NewResolver(s *store.Store) *Resolver {
	return &Resolver{
		Store: s,
		Fetch: func(ctx context.Context, sub model.Sub) (string, error) {
			return downloader.NewClient().Fetch(ctx, sub)
		},
	}
}

// TargetName returns the token payload for a token string.
func (r *Resolver) Lookup(token string) (map[string]any, error) {
	return r.Store.GetToken(token)
}

// CheckAndConsume validates that a token is currently usable and, for
// count-mode tokens, atomically increments its usage. It's used by share
// paths (like plain file downloads) that don't go through Resolve's
// pipeline processing.
func (r *Resolver) CheckAndConsume(tokenStr string) error {
	rec, err := r.Store.GetToken(tokenStr)
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("invalid token")
	}
	var t model.Token
	if err := remarshal(rec, &t); err != nil {
		return err
	}
	if !t.Usable() {
		return fmt.Errorf("token expired")
	}
	if t.Mode == "count" {
		t.UsedCount++
		updated, _ := json.Marshal(t)
		var m map[string]any
		_ = json.Unmarshal(updated, &m)
		for k, v := range rec {
			if _, ok := m[k]; !ok {
				m[k] = v
			}
		}
		if err := r.Store.UpdateToken(m); err != nil {
			return err
		}
	}
	return nil
}

// Resolve processes a shared download for the given token and target.
func (r *Resolver) Resolve(ctx context.Context, tokenStr, target string) (string, error) {
	rec, err := r.Store.GetToken(tokenStr)
	if err != nil {
		return "", err
	}
	if rec == nil {
		return "", fmt.Errorf("invalid token")
	}

	var t model.Token
	if err := remarshal(rec, &t); err != nil {
		return "", err
	}
	if !t.Usable() {
		return "", fmt.Errorf("token expired")
	}

	raw, err := r.resolveRaw(ctx, t)
	if err != nil {
		return "", err
	}

	var operators []model.Operator
	switch t.Type {
	case "sub":
		if ops, ok := rec["process"].([]any); ok {
			operators = decodeOperators(ops)
		}
	case "col":
		if ops, ok := rec["process"].([]any); ok {
			operators = decodeOperators(ops)
		}
	}

	prependLines := decodeLines(rec["prependLines"])
	appendLines := decodeLines(rec["appendLines"])

	req := pipeline.Request{
		Raw:          raw,
		Target:       target,
		IncludeProxies: true,
		Operators:    operators,
		PrependLines: prependLines,
		AppendLines:  appendLines,
		Useless:      false,
	}

	// count-based tokens are consumed on success
	body, err := pipeline.Process(req)
	if err != nil {
		return "", err
	}
	if t.Mode == "count" {
		t.UsedCount++
		updated, _ := json.Marshal(t)
		var m map[string]any
		_ = json.Unmarshal(updated, &m)
		for k, v := range rec {
			if _, ok := m[k]; !ok {
				m[k] = v
			}
		}
		_ = r.Store.UpdateToken(m)
	}
	return body, nil
}

func (r *Resolver) resolveRaw(ctx context.Context, t model.Token) (string, error) {
	switch t.Type {
	case "sub":
		rec, err := r.Store.GetSub(t.Name)
		if err != nil || rec == nil {
			return "", fmt.Errorf("subscription %q not found", t.Name)
		}
		var sub model.Sub
		if err := remarshal(rec, &sub); err != nil {
			return "", err
		}
		raw, err := r.Fetch(ctx, sub)
		if err != nil {
			return "", err
		}
		// mergeSources is disabled for shared downloads (no override injection)
		return raw, nil
	case "col":
		rec, err := r.Store.GetCollection(t.Name)
		if err != nil || rec == nil {
			return "", fmt.Errorf("collection %q not found", t.Name)
		}
		var col model.Collection
		if err := remarshal(rec, &col); err != nil {
			return "", err
		}
		proxies := []*model.Proxy{}
		for _, subName := range col.Subscriptions {
			subRec, err := r.Store.GetSub(subName)
			if err != nil || subRec == nil {
				continue
			}
			var sub model.Sub
			if err := remarshal(subRec, &sub); err != nil {
				continue
			}
			content, err := r.Fetch(ctx, sub)
			if err != nil {
				continue
			}
			proxies = append(proxies, pipeline.Parse(content)...)
		}
		return marshalProxies(proxies)
	default:
		return "", fmt.Errorf("unsupported token type: %s", t.Type)
	}
}

// marshalProxies joins proxies back into a single parseable text blob.
func marshalProxies(proxies []*model.Proxy) (string, error) {
	var sb strings.Builder
	for i, p := range proxies {
		if i > 0 {
			sb.WriteString("\n")
		}
		b, err := json.Marshal(p)
		if err != nil {
			return "", err
		}
		sb.Write(b)
	}
	return sb.String(), nil
}

// FetchSub downloads the raw content of a subscription.
func (r *Resolver) FetchSub(ctx context.Context, sub model.Sub) (string, error) {
	return r.Fetch(ctx, sub)
}

// PreviewSub fetches and parses a subscription without producing output.
func (r *Resolver) PreviewSub(ctx context.Context, sub model.Sub) ([]*model.Proxy, error) {
	raw, err := r.Fetch(ctx, sub)
	if err != nil {
		return nil, err
	}
	return pipeline.Parse(raw), nil
}

// Remarshal converts a map into a struct via JSON.
func Remarshal(m map[string]any, v any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func remarshal(m map[string]any, v any) error {
	return Remarshal(m, v)
}

func decodeOperators(ops []any) []model.Operator {
	out := make([]model.Operator, 0, len(ops))
	for _, o := range ops {
		b, _ := json.Marshal(o)
		var op model.Operator
		if err := json.Unmarshal(b, &op); err == nil {
			out = append(out, op)
		}
	}
	return out
}

func decodeLines(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
