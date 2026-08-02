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
//
// Supported variables (all lowercase, no legacy aliases):
//
//	host             listen host, default "0.0.0.0"
//	port             listen port, default 3000
//	data_dir         data directory, default "./data"
//	jwt_secret       JWT signing secret; auto-generated and persisted under
//	                 data_dir if unset
//	token_ttl_hours  login JWT lifetime in hours, default 168 (7 days)
//	user             admin username, default "admin"
//	password         admin password, default "admin"
func Load() *Config {
	dataDir := getenv("data_dir", "./data")
	return &Config{
		Host:          getenv("host", "0.0.0.0"),
		Port:          getenvInt("port", 3000),
		DataDir:       dataDir,
		DBPath:        filepath.Join(dataDir, "substore.db"),
		JWTSecret:     loadOrCreateJWTSecret(dataDir),
		TokenTTLHours: getenvInt("token_ttl_hours", 24*7),
		AdminUsername: getenv("user", "admin"),
		AdminPassword: getenv("password", "admin"),
	}
}

// loadOrCreateJWTSecret returns the configured JWT secret, or generates and
// persists a random one under the data directory so tokens survive restarts.
func loadOrCreateJWTSecret(dataDir string) string {
	if v := os.Getenv("jwt_secret"); v != "" {
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
