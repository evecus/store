package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func (s *Server) handleListCollections(c *gin.Context) {
	cols, err := s.Store.ListCollections()
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	c.JSON(http.StatusOK, cols)
}

func (s *Server) handleCreateCollection(c *gin.Context) {
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
	existing, err := s.Store.GetCollection(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if existing != nil {
		abortError(c, http.StatusConflict, "collection already exists")
		return
	}
	position := getStr(body, "position")
	if position == "" {
		position = "bottom"
	}
	if err := s.Store.UpsertCollection(name, body, position); err != nil {
		abortError(c, http.StatusInternalServerError, "save failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "success", "name": name})
}

func (s *Server) handleGetCollection(c *gin.Context) {
	name := c.Param("name")
	col, err := s.Store.GetCollection(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if col == nil {
		abortError(c, http.StatusNotFound, "collection not found")
		return
	}
	c.JSON(http.StatusOK, col)
}

func (s *Server) handlePatchCollection(c *gin.Context) {
	name := c.Param("name")
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		abortError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	existing, err := s.Store.GetCollection(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if existing == nil {
		abortError(c, http.StatusNotFound, "collection not found")
		return
	}
	newName := name
	if n, ok := body["name"].(string); ok && n != "" && n != name {
		if dup, _ := s.Store.GetCollection(n); dup != nil {
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
	if err := s.Store.UpsertCollection(newName, existing, "bottom"); err != nil {
		abortError(c, http.StatusInternalServerError, "save failed")
		return
	}
	if newName != name {
		_ = s.Store.DeleteCollection(name)
	}
	c.JSON(http.StatusOK, gin.H{"message": "success", "name": newName})
}

func (s *Server) handleDeleteCollection(c *gin.Context) {
	name := c.Param("name")
	existing, err := s.Store.GetCollection(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if existing == nil {
		abortError(c, http.StatusNotFound, "collection not found")
		return
	}
	if err := s.Store.DeleteCollection(name); err != nil {
		abortError(c, http.StatusInternalServerError, "delete failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "success"})
}
