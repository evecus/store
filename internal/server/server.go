package server

import (
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"substore/internal/config"
	"substore/internal/share"
	"substore/internal/store"
	"substore/web"
)

// Server wires routes, middleware and handlers.
type Server struct {
	Cfg    *config.Config
	Store  *store.Store
	Share  *share.Resolver
	router *gin.Engine

	loginLimiter    *rateLimiter
	downloadLimiter *rateLimiter
}

// New builds a Server and its route tree.
func New(cfg *config.Config, st *store.Store) *Server {
	s := &Server{
		Cfg:   cfg,
		Store: st,
		Share: share.NewResolver(st),
		// 10 failed-or-otherwise login attempts per IP per 15 minutes.
		loginLimiter: newRateLimiter(10, 15*time.Minute),
		// 120 requests per IP per minute against the public
		// download/share endpoints.
		downloadLimiter: newRateLimiter(120, time.Minute),
	}
	s.router = s.buildRouter()
	return s
}

// Run starts the HTTP server.
func (s *Server) Run() error {
	addr := fmt.Sprintf("%s:%d", s.Cfg.Host, s.Cfg.Port)
	log.Printf("substore listening on %s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *Server) buildRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(quietLogger(), gin.Recovery(), securityHeaders())
	r.MaxMultipartMemory = 8 << 20

	api := r.Group("/api")

	// auth
	api.POST("/login", s.loginRateLimit(), s.handleLogin)

	authed := api.Group("")
	authed.Use(s.authMiddleware())
	{
		authed.GET("/me", s.handleMe)

		// subscriptions
		authed.GET("/subs", s.handleListSubs)
		authed.POST("/subs", s.handleCreateSub)
		authed.GET("/sub/:name", s.handleGetSub)
		authed.PATCH("/sub/:name", s.handlePatchSub)
		authed.DELETE("/sub/:name", s.handleDeleteSub)

		// collections
		authed.GET("/collections", s.handleListCollections)
		authed.POST("/collections", s.handleCreateCollection)
		authed.GET("/col/:name", s.handleGetCollection)
		authed.PATCH("/col/:name", s.handlePatchCollection)
		authed.DELETE("/col/:name", s.handleDeleteCollection)

		// files
		authed.GET("/files", s.handleListFiles)
		authed.POST("/files", s.handleCreateFile)
		authed.GET("/file/:name", s.handleGetFile)
		authed.PATCH("/file/:name", s.handlePatchFile)
		authed.DELETE("/file/:name", s.handleDeleteFile)

		// preview
		authed.GET("/node-info/:name", s.handleNodeInfo)

		// tokens
		authed.GET("/tokens", s.handleListTokens)
		authed.POST("/token", s.handleCreateToken)
		authed.DELETE("/token/:token", s.handleDeleteToken)

		// targets
		authed.GET("/targets", s.handleTargets)

		// settings
		authed.GET("/settings", s.handleGetSettings)
		authed.PATCH("/settings", s.handlePatchSettings)
	}

	// shared endpoints
	r.GET("/download/:name", s.downloadRateLimit(), s.handleDownload)
	r.GET("/api/file/:name/raw", s.handleFileRaw)
	r.GET("/share/sub/:name", s.downloadRateLimit(), s.handleShareDownload)
	r.GET("/share/col/:name", s.downloadRateLimit(), s.handleShareDownload)
	r.GET("/share/file/:name", s.downloadRateLimit(), s.handleShareDownload)

	// static frontend
	s.mountFrontend(r)

	return r
}

// quietLogger only logs requests that fail (status >= 400), so normal
// traffic doesn't spam stdout the way gin.Logger() does.
func quietLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		c.Next()
		status := c.Writer.Status()
		if status >= http.StatusBadRequest {
			log.Printf("%d %s %s (%s)", status, c.Request.Method, path, time.Since(start).Round(time.Millisecond))
		}
	}
}

// mountFrontend serves the embedded web frontend.
func (s *Server) mountFrontend(r *gin.Engine) {
	var dist fs.FS
	if web.HasIndex() {
		dist = web.Dist()
	}
	if dist == nil {
		log.Printf("frontend not found (embedded dist is empty), API only")
		return
	}
	fileServer := http.FileServer(http.FS(dist))
	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"message": "not found"})
			return
		}
		path := strings.TrimPrefix(c.Request.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if f, err := fs.Stat(dist, path); err == nil && !f.IsDir() {
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}
		if _, err := fs.Stat(dist, "index.html"); err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Request.URL.Path = "/index.html"
		fileServer.ServeHTTP(c.Writer, c.Request)
	})
}

// ---- auth helpers ----

// BootstrapAdmin logs a warning if the admin account is still using the
// default credentials. The admin account is never persisted to the
// database: username/password always come straight from Cfg (set via the
// `auth` environment variable, or "admin:admin" by default), so restarting
// with a different `auth` value takes effect immediately and old
// credentials never linger.
func (s *Server) BootstrapAdmin() error {
	if s.Cfg.AdminUsername == "admin" && s.Cfg.AdminPassword == "admin" {
		log.Printf("WARNING: admin account is using the default credentials \"admin:admin\" — set the `auth` environment variable (e.g. auth=myuser:mypassword) to a strong value before exposing this server to the network")
	}
	return nil
}

// ---- context helpers ----

func currentUser(c *gin.Context) string {
	if v, ok := c.Get("username"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func abortError(c *gin.Context, status int, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"message": msg})
}
