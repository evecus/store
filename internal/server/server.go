package server

import (
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

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
}

// New builds a Server and its route tree.
func New(cfg *config.Config, st *store.Store) *Server {
	s := &Server{
		Cfg:   cfg,
		Store: st,
		Share: share.NewResolver(st),
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
	r.Use(quietLogger(), gin.Recovery())
	r.MaxMultipartMemory = 8 << 20

	api := r.Group("/api")

	// auth
	api.POST("/login", s.handleLogin)

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
	r.GET("/download/:name", s.handleDownload)
	r.GET("/share/sub/:name", s.handleShareDownload)
	r.GET("/share/col/:name", s.handleShareDownload)

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

// mountFrontend serves the embedded web frontend, falling back to the
// on-disk directory when the frontend has not been built into the binary.
func (s *Server) mountFrontend(r *gin.Engine) {
	var dist fs.FS
	if web.HasIndex() {
		dist = web.Dist()
	} else if dir := s.Cfg.FrontendPath; dir != "" {
		if _, err := os.Stat(dir + "/index.html"); err == nil {
			dist = os.DirFS(dir)
		}
	}
	if dist == nil {
		log.Printf("frontend not found (no embedded dist, %s missing), API only", s.Cfg.FrontendPath+"/index.html")
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

func (s *Server) hashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ensureAdminUser creates or updates the admin account so the configured
// environment-variable credentials are always authoritative at startup.
func (s *Server) ensureAdminUser() error {
	hash, err := s.hashPassword(s.Cfg.AdminPassword)
	if err != nil {
		return err
	}
	u, err := s.Store.GetUser(s.Cfg.AdminUsername)
	if err != nil {
		return err
	}
	if u == nil {
		return s.Store.CreateUser(s.Cfg.AdminUsername, hash)
	}
	return s.Store.UpdateUserPassword(s.Cfg.AdminUsername, hash)
}

// BootstrapAdmin ensures the admin user exists when an admin password is set.
func (s *Server) BootstrapAdmin() error {
	return s.ensureAdminUser()
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
