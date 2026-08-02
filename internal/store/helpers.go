package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// queryMap scans a single JSON column row into a map.
func (s *Store) queryMap(query string, arg any) (map[string]any, error) {
	var raw string
	var err error
	if arg != nil {
		err = s.db.QueryRow(query, arg).Scan(&raw)
	} else {
		err = s.db.QueryRow(query).Scan(&raw)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// queryMaps scans all rows of a single JSON column into a list of maps.
func (s *Store) queryMaps(query string, dest *[]map[string]any) error {
	rows, err := s.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			return err
		}
		if m == nil {
			m = map[string]any{}
		}
		*dest = append(*dest, m)
	}
	return rows.Err()
}

// upsertMap inserts or updates a row in a name-keyed table.
func (s *Store) upsertMap(table, name string, data map[string]any, position string) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	pos := 0
	if position == "top" {
		err = s.db.QueryRow(fmt.Sprintf("SELECT COALESCE(MIN(pos), 1) - 1 FROM %s", table)).Scan(&pos)
	} else {
		err = s.db.QueryRow(fmt.Sprintf("SELECT COALESCE(MAX(pos), 0) + 1 FROM %s", table)).Scan(&pos)
	}
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		fmt.Sprintf("INSERT INTO %s (name, data, pos) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET data = excluded.data", table),
		name, string(b), pos,
	)
	return err
}
