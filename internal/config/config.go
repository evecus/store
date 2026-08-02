package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
)

// Config holds runtime configuration resolved from environment variables.
type Config struct {
	Host          string
	Port          int
	DataDir       string
	DBPath        string
	JWTSecret     string
	TokenTTLHours int
	AdminUsername string
	AdminPassword string
	FrontendPath  string
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// Load reads configuration from environment variables.
func Load() *Config {
	dataDir := dataDirPath()
	return &Config{
		Host:          getenv("SUB_STORE_BACKEND_API_HOST", "0.0.0.0"),
		Port:          httpPort(),
		DataDir:       dataDir,
		DBPath:        filepath.Join(dataDir, "substore.db"),
		JWTSecret:     loadOrCreateJWTSecret(dataDir),
		TokenTTLHours: getenvInt("SUB_STORE_TOKEN_TTL_HOURS", 24*7),
		AdminUsername: getenv("SUB_STORE_ADMIN_USERNAME", "admin"),
		AdminPassword: getenv("SUB_STORE_ADMIN_PASSWORD", "admin"),
		FrontendPath:  getenv("SUB_STORE_FRONTEND_PATH", "./web/dist"),
	}
}

// httpPort resolves the HTTP listen port. SUB_STORE_HTTP_PORT takes
// precedence; SUB_STORE_BACKEND_API_PORT is kept for backward compatibility.
func httpPort() int {
	if v := os.Getenv("SUB_STORE_HTTP_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return getenvInt("SUB_STORE_BACKEND_API_PORT", 3000)
}

// dataDirPath resolves the data directory. SUB_STORE_DATA_DIR takes
// precedence; SUB_STORE_DATA_PATH is kept for backward compatibility.
func dataDirPath() string {
	if v := os.Getenv("SUB_STORE_DATA_DIR"); v != "" {
		return v
	}
	return getenv("SUB_STORE_DATA_PATH", "./data")
}

// loadOrCreateJWTSecret returns the configured JWT secret, or generates and
// persists a random one under the data directory so tokens survive restarts.
func loadOrCreateJWTSecret(dataDir string) string {
	if v := os.Getenv("SUB_STORE_JWT_SECRET"); v != "" {
		return v
	}
	path := filepath.Join(dataDir, "jwt_secret")
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		return string(b)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "substore-generated-secret"
	}
	secret := hex.EncodeToString(buf)
	if err := os.MkdirAll(dataDir, 0o755); err == nil {
		_ = os.WriteFile(path, []byte(secret), 0o600)
	}
	return secret
}
