package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database and provides typed accessors for each
// entity type.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database at path.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS users (
			username     TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			created_at   INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS subs (
			id   INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			data TEXT NOT NULL,
			pos  INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS collections (
			id   INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			data TEXT NOT NULL,
			pos  INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS tokens (
			id   INTEGER PRIMARY KEY AUTOINCREMENT,
			token TEXT NOT NULL UNIQUE,
			data TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
	}
	for _, q := range schema {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// ---- generic helpers ----

// listEntity loads all rows of a table ordered by position, unmarshalling
// each row's data JSON into the provided constructor result.
func listEntity[T any](s *Store, table string, dest *[]T) error {
	rows, err := s.db.Query(fmt.Sprintf("SELECT data FROM %s ORDER BY pos ASC, id ASC", table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		var item T
		if err := json.Unmarshal([]byte(raw), &item); err != nil {
			return err
		}
		*dest = append(*dest, item)
	}
	return rows.Err()
}

func getEntity[T any](s *Store, table, name string, dest *T) (bool, error) {
	var raw string
	err := s.db.QueryRow(fmt.Sprintf("SELECT data FROM %s WHERE name = ?", table), name).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal([]byte(raw), dest); err != nil {
		return false, err
	}
	return true, nil
}

func upsertEntity[T any](s *Store, table, name string, item T, position string) error {
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	var pos int
	if position == "top" {
		err = s.db.QueryRow(fmt.Sprintf("SELECT COALESCE(MIN(pos), 1) - 1 FROM %s", table)).Scan(&pos)
		if err != nil {
			return err
		}
	} else {
		err = s.db.QueryRow(fmt.Sprintf("SELECT COALESCE(MAX(pos), 0) + 1 FROM %s", table)).Scan(&pos)
		if err != nil {
			return err
		}
	}
	_, err = s.db.Exec(
		fmt.Sprintf("INSERT INTO %s (name, data, pos) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET data = excluded.data", table),
		name, string(data), pos,
	)
	return err
}

func deleteEntity(s *Store, table, name string) error {
	_, err := s.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE name = ?", table), name)
	return err
}

// ---- users ----

// User is a stored account.
type User struct {
	Username     string
	PasswordHash string
	CreatedAt    int64
}

// CreateUser inserts a new user.
func (s *Store) CreateUser(username, passwordHash string) error {
	_, err := s.db.Exec(
		"INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
		username, passwordHash, time.Now().UnixMilli(),
	)
	return err
}

// GetUser returns a user by username.
func (s *Store) GetUser(username string) (*User, error) {
	var u User
	err := s.db.QueryRow(
		"SELECT username, password_hash, created_at FROM users WHERE username = ?",
		username,
	).Scan(&u.Username, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// UserCount returns the total number of users.
func (s *Store) UserCount() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

// UpdateUserPassword updates the password hash of a user.
func (s *Store) UpdateUserPassword(username, passwordHash string) error {
	_, err := s.db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", passwordHash, username)
	return err
}

// ---- subs ----

// ListSubs returns all subscriptions.
func (s *Store) ListSubs() ([]map[string]any, error) {
	out := []map[string]any{}
	err := s.queryMaps("SELECT data FROM subs ORDER BY pos ASC, id ASC", &out)
	return out, err
}

// GetSub returns a subscription by name.
func (s *Store) GetSub(name string) (map[string]any, error) {
	return s.queryMap("SELECT data FROM subs WHERE name = ?", name)
}

// UpsertSub inserts or updates a subscription.
func (s *Store) UpsertSub(name string, data map[string]any, position string) error {
	return s.upsertMap("subs", name, data, position)
}

// DeleteSub removes a subscription.
func (s *Store) DeleteSub(name string) error {
	return deleteEntity(s, "subs", name)
}

// ---- collections ----

func (s *Store) ListCollections() ([]map[string]any, error) {
	out := []map[string]any{}
	err := s.queryMaps("SELECT data FROM collections ORDER BY pos ASC, id ASC", &out)
	return out, err
}

func (s *Store) GetCollection(name string) (map[string]any, error) {
	return s.queryMap("SELECT data FROM collections WHERE name = ?", name)
}

func (s *Store) UpsertCollection(name string, data map[string]any, position string) error {
	return s.upsertMap("collections", name, data, position)
}

func (s *Store) DeleteCollection(name string) error {
	return deleteEntity(s, "collections", name)
}

// ---- tokens ----

func (s *Store) ListTokens() ([]map[string]any, error) {
	out := []map[string]any{}
	err := s.queryMaps("SELECT data FROM tokens ORDER BY id ASC", &out)
	return out, err
}

func (s *Store) GetToken(token string) (map[string]any, error) {
	return s.queryMap("SELECT data FROM tokens WHERE token = ?", token)
}

func (s *Store) InsertToken(data map[string]any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	token, _ := data["token"].(string)
	_, err = s.db.Exec("INSERT INTO tokens (token, data) VALUES (?, ?)", token, string(b))
	return err
}

func (s *Store) UpdateToken(data map[string]any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	token, _ := data["token"].(string)
	_, err = s.db.Exec("UPDATE tokens SET data = ? WHERE token = ?", string(b), token)
	return err
}

func (s *Store) DeleteToken(token string) error {
	_, err := s.db.Exec("DELETE FROM tokens WHERE token = ?", token)
	return err
}

// ---- settings ----

func (s *Store) GetSettings() (map[string]any, error) {
	return s.queryMap("SELECT value FROM settings WHERE key = 'settings'", "")
}

func (s *Store) SaveSettings(v map[string]any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		"INSERT INTO settings (key, value) VALUES ('settings', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		string(b),
	)
	return err
}
