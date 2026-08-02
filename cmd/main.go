package main

import (
	"log"

	"substore/internal/config"
	"substore/internal/server"
	"substore/internal/store"
)

func main() {
	cfg := config.Load()

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer st.Close()

	srv := server.New(cfg, st)
	if err := srv.BootstrapAdmin(); err != nil {
		log.Fatalf("bootstrap admin: %v", err)
	}
	if err := srv.Run(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
