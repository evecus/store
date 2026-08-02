package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"substore/internal/model"
	"substore/internal/pipeline"
	"substore/internal/share"
)

// contentTypeFor maps a target to a response Content-Type.
func contentTypeFor(target string) string {
	switch strings.ToLower(target) {
	case "json":
		return "application/json; charset=utf-8"
	case "clash", "mihomo", "stash":
		return "text/yaml; charset=utf-8"
	case "sing-box", "v2ray":
		return "application/json; charset=utf-8"
	default:
		return "text/plain; charset=utf-8"
	}
}

// handleDownload serves /download/:name (subscription) with optional token or
// bearer auth.
func (s *Server) handleDownload(c *gin.Context) {
	name := c.Param("name")
	target := strings.TrimSpace(c.DefaultQuery("target", "mihomo"))
	if target == "" {
		target = "mihomo"
	}
	authorized := s.authorizeDownload(c)
	if !authorized {
		abortError(c, http.StatusUnauthorized, "unauthorized")
		return
	}
	rec, err := s.Store.GetSub(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if rec != nil {
		s.downloadSub(c, rec, name, target)
		return
	}
	s.downloadCollection(c, name, target)
}

// handleShareDownload serves /share/sub/:name and /share/col/:name.
func (s *Server) handleShareDownload(c *gin.Context) {
	name := c.Param("name")
	target := strings.TrimSpace(c.Query("target"))
	token := strings.TrimSpace(c.Query("token"))
	if token == "" {
		abortError(c, http.StatusBadRequest, "missing token")
		return
	}
	kind := "sub"
	if strings.HasPrefix(c.FullPath(), "/share/col") {
		kind = "col"
	}
	rec, err := s.Share.Lookup(token)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if rec == nil {
		abortError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	if getStr(rec, "type") != kind || getStr(rec, "name") != name {
		abortError(c, http.StatusUnauthorized, "token does not match target")
		return
	}
	// prefer the explicit query target, else the target chosen at token creation
	if target == "" {
		target = getStr(rec, "target")
	}
	if target == "" {
		target = "mihomo"
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	body, err := s.Share.Resolve(ctx, token, target)
	if err != nil {
		abortError(c, http.StatusBadRequest, err.Error())
		return
	}
	if c.Query("preview") == "1" {
		renderSharePreview(c, name, target, body, s)
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.%s"`, name, fileExt(target)))
	c.Header("Content-Type", contentTypeFor(target))
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, "%s", body)
}

// renderSharePreview serves a pure raw-text preview of a share result, with
// no chrome: just the plain content, like a GitHub raw file view.
func renderSharePreview(c *gin.Context, name, target, body string, s *Server) {
	html := `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + template.HTMLEscapeString(name) + `.` + template.HTMLEscapeString(fileExt(target)) + `</title>
<style>
:root{color-scheme:light}
html,body{margin:0;padding:0;background:#ffffff}
pre{margin:0;padding:16px;white-space:pre-wrap;word-break:break-all;font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace;font-size:12px;line-height:1.5;color:#1f2328}
</style>
</head>
<body>
<pre>` + template.HTMLEscapeString(body) + `</pre>
</body>
</html>`
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, "%s", html)
}

// authorizeDownload accepts either a valid share token, a JWT bearer, or a
// JWT passed as ?token= (needed for opening /download in a new browser tab,
// where an Authorization header can't be attached).
func (s *Server) authorizeDownload(c *gin.Context) bool {
	header := c.GetHeader("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		_, err := s.validateToken(strings.TrimPrefix(header, "Bearer "))
		return err == nil
	}
	if token := strings.TrimSpace(c.Query("token")); token != "" {
		if _, err := s.validateToken(token); err == nil {
			return true
		}
		rec, err := s.Share.Lookup(token)
		return err == nil && rec != nil
	}
	return false
}

func (s *Server) downloadSub(c *gin.Context, rec map[string]any, name, target string) {
	var sub model.Sub
	if err := share.Remarshal(rec, &sub); err != nil {
		abortError(c, http.StatusInternalServerError, "decode failed")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	raw, err := s.Share.FetchSub(ctx, sub)
	if err != nil {
		abortError(c, http.StatusBadGateway, "fetch failed: "+err.Error())
		return
	}
	req := pipeline.Request{
		Raw:          raw,
		Target:       target,
		IncludeProxies: true,
		Operators:    sub.Process,
		PrependLines: decodeLines(rec["prependLines"]),
		AppendLines:  decodeLines(rec["appendLines"]),
		Useless:      false,
	}
	body, err := pipeline.Process(req)
	if err != nil {
		abortError(c, http.StatusBadRequest, err.Error())
		return
	}
	if c.Query("preview") == "1" {
		renderSharePreview(c, name, target, body, s)
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.%s"`, name, fileExt(target)))
	c.Header("Content-Type", contentTypeFor(target))
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, "%s", body)
}

func (s *Server) downloadCollection(c *gin.Context, name, target string) {
	rec, err := s.Store.GetCollection(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if rec == nil {
		abortError(c, http.StatusNotFound, "subscription or collection not found")
		return
	}
	var col model.Collection
	if err := share.Remarshal(rec, &col); err != nil {
		abortError(c, http.StatusInternalServerError, "decode failed")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
	defer cancel()
	proxies := []*model.Proxy{}
	for _, subName := range col.Subscriptions {
		subRec, err := s.Store.GetSub(subName)
		if err != nil || subRec == nil {
			continue
		}
		var sub model.Sub
		if err := share.Remarshal(subRec, &sub); err != nil {
			continue
		}
		content, err := s.Share.FetchSub(ctx, sub)
		if err != nil {
			continue
		}
		proxies = append(proxies, pipeline.Parse(content)...)
	}
	raw := marshalProxiesText(proxies)
	req := pipeline.Request{
		Raw:          raw,
		Target:       target,
		IncludeProxies: true,
		Operators:    col.Process,
		PrependLines: decodeLines(rec["prependLines"]),
		AppendLines:  decodeLines(rec["appendLines"]),
		Useless:      false,
	}
	body, err := pipeline.Process(req)
	if err != nil {
		abortError(c, http.StatusBadRequest, err.Error())
		return
	}
	body, err := pipeline.Process(req)
	if err != nil {
		abortError(c, http.StatusBadRequest, err.Error())
		return
	}
	if c.Query("preview") == "1" {
		renderSharePreview(c, name, target, body, s)
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.%s"`, name, fileExt(target)))
	c.Header("Content-Type", contentTypeFor(target))
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, "%s", body)
}

func marshalProxiesText(proxies []*model.Proxy) string {
	var sb strings.Builder
	for i, p := range proxies {
		if i > 0 {
			sb.WriteString("\n")
		}
		b, err := json.Marshal(p)
		if err != nil {
			continue
		}
		sb.Write(b)
	}
	return sb.String()
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

func fileExt(target string) string {
	switch strings.ToLower(target) {
	case "json", "sing-box", "v2ray":
		return "json"
	case "clash", "mihomo", "stash":
		return "yaml"
	default:
		return "conf"
	}
}
