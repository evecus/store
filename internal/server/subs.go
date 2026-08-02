package server

import (
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"substore/internal/model"
	"substore/internal/share"
)

func (s *Server) handleListSubs(c *gin.Context) {
	subs, err := s.Store.ListSubs()
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	c.JSON(http.StatusOK, subs)
}

func (s *Server) handleCreateSub(c *gin.Context) {
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		abortError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	name := strings.TrimSpace(getStr(body, "name"))
	if name == "" {
		abortError(c, http.StatusBadRequest, "name is required")
		return
	}
	existing, err := s.Store.GetSub(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if existing != nil {
		abortError(c, http.StatusConflict, "subscription already exists")
		return
	}
	position := getStr(body, "position")
	if position == "" {
		position = "bottom"
	}
	if err := s.Store.UpsertSub(name, body, position); err != nil {
		abortError(c, http.StatusInternalServerError, "save failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "success", "name": name})
}

func (s *Server) handleGetSub(c *gin.Context) {
	name := c.Param("name")
	sub, err := s.Store.GetSub(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if sub == nil {
		abortError(c, http.StatusNotFound, "subscription not found")
		return
	}
	c.JSON(http.StatusOK, sub)
}

func (s *Server) handlePatchSub(c *gin.Context) {
	name := c.Param("name")
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		abortError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	existing, err := s.Store.GetSub(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if existing == nil {
		abortError(c, http.StatusNotFound, "subscription not found")
		return
	}
	// rename support
	newName := name
	if n, ok := body["name"].(string); ok && n != "" && n != name {
		if dup, _ := s.Store.GetSub(n); dup != nil {
			abortError(c, http.StatusConflict, "name already taken")
			return
		}
		newName = n
	}
	for k, v := range body {
		if k == "name" {
			existing["name"] = v
			continue
		}
		existing[k] = v
	}
	if err := s.Store.UpsertSub(newName, existing, "bottom"); err != nil {
		abortError(c, http.StatusInternalServerError, "save failed")
		return
	}
	if newName != name {
		_ = s.Store.DeleteSub(name)
	}
	c.JSON(http.StatusOK, gin.H{"message": "success", "name": newName})
}

func (s *Server) handleDeleteSub(c *gin.Context) {
	name := c.Param("name")
	existing, err := s.Store.GetSub(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if existing == nil {
		abortError(c, http.StatusNotFound, "subscription not found")
		return
	}
	if err := s.Store.DeleteSub(name); err != nil {
		abortError(c, http.StatusInternalServerError, "delete failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "success"})
}

// handleNodeInfo returns a JSON preview of a subscription's parsed nodes.
func (s *Server) handleNodeInfo(c *gin.Context) {
	name := c.Param("name")
	rec, err := s.Store.GetSub(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if rec == nil {
		abortError(c, http.StatusNotFound, "subscription not found")
		return
	}
	var sub model.Sub
	if err := share.Remarshal(rec, &sub); err != nil {
		abortError(c, http.StatusInternalServerError, "decode failed")
		return
	}
	proxies, err := s.Share.PreviewSub(c, sub)
	if err != nil {
		abortError(c, http.StatusBadGateway, err.Error())
		return
	}
	c.JSON(http.StatusOK, proxies)
}

func getStr(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
