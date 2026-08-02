package server

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"substore/internal/model"
	"substore/internal/producer"
	"substore/internal/share"
)

func (s *Server) handleListTokens(c *gin.Context) {
	tokens, err := s.Store.ListTokens()
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	c.JSON(http.StatusOK, tokens)
}

func (s *Server) handleCreateToken(c *gin.Context) {
	var body struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Mode    string `json:"mode"`
		Exp     int64  `json:"exp"`
		Seconds int    `json:"seconds"`
		Count   int    `json:"count"`
		Target  string `json:"target"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		abortError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Type != "sub" && body.Type != "col" {
		abortError(c, http.StatusBadRequest, "type must be sub or col")
		return
	}
	if body.Target == "" {
		body.Target = "mihomo"
	}
	if !producer.Known(body.Target) {
		abortError(c, http.StatusBadRequest, "unsupported target: "+body.Target)
		return
	}
	// validate the target exists
	if body.Type == "sub" {
		if sub, _ := s.Store.GetSub(body.Name); sub == nil {
			abortError(c, http.StatusNotFound, "subscription not found")
			return
		}
	} else {
		if col, _ := s.Store.GetCollection(body.Name); col == nil {
			abortError(c, http.StatusNotFound, "collection not found")
			return
		}
	}
	opts := map[string]any{
		"mode":    body.Mode,
		"seconds": body.Seconds,
		"exp":     body.Exp,
		"count":   body.Count,
		"target":  body.Target,
	}
	token, err := share.BuildTokenPayload(body.Type, body.Name, opts)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "token generation failed")
		return
	}
	payload := tokenPayloadMap(token)
	if err := s.Store.InsertToken(payload); err != nil {
		abortError(c, http.StatusInternalServerError, "save token failed")
		return
	}
	c.JSON(http.StatusOK, payload)
}

// handleTargets lists the supported output target formats.
func (s *Server) handleTargets(c *gin.Context) {
	c.JSON(http.StatusOK, producer.Names())
}

func (s *Server) handleDeleteToken(c *gin.Context) {
	token := c.Param("token")
	if err := s.Store.DeleteToken(token); err != nil {
		abortError(c, http.StatusInternalServerError, "delete failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "success"})
}

func tokenPayloadMap(t model.Token) map[string]any {
	b, err := json.Marshal(t)
	if err != nil {
		return map[string]any{"token": t.Token, "type": t.Type, "name": t.Name}
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}
