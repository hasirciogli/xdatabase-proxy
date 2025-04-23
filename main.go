// main.go
package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/hasirciogli/xdatabase-proxy/pkg/postgresql"
)

var (
	isReady   atomic.Bool
	isHealthy atomic.Bool
)

func setupHealthChecks() {
	// Set initial state
	isHealthy.Store(true)
	isReady.Store(true)

	// Health check endpoint
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if isHealthy.Load() {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("healthy"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("unhealthy"))
	})

	// Readiness check endpoint
	http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		if isReady.Load() {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ready"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("not ready"))
	})

	// Start HTTP server for health checks
	go func() {
		if err := http.ListenAndServe(":80", nil); err != nil {
			log.Printf("Health check server error: %v", err)
		}
	}()
}

func main() {
	// Setup health check endpoints (!!!CURRENTLY NOT USED!!!)
	setupHealthChecks()

	proxy, err := postgresql.NewPostgresProxy("local-test")
	if err != nil {
		log.Fatalf("Failed to create PostgreSQL proxy: %v", err)
	}

	go proxy.Start(1881, "", "")

	// Wait for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	// Mark as not ready and unhealthy during shutdown
	isReady.Store(false)
	isHealthy.Store(false)

	log.Println("Shutting down...")
}
