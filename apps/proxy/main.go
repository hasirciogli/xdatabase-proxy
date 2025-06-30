// main.go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/hasirciogli/xdatabase-proxy/pkg/postgresql"
)

var (
	isReady       atomic.Bool
	isHealthy     atomic.Bool
	wg            sync.WaitGroup
	postgresProxy *postgresql.PostgresProxy
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

func startPostgresProxy(ctx context.Context, wg *sync.WaitGroup) {
	postgresqlProxyEnabled := os.Getenv("POSTGRESQL_PROXY_ENABLED")
	if postgresqlProxyEnabled == "" {
		log.Println("PostgreSQL proxy is not enabled (passed in POSTGRESQL_PROXY_ENABLED)")
		return
	}

	startPort := os.Getenv("POSTGRESQL_PROXY_START_PORT")
	if startPort == "" {
		panic("POSTGRESQL_PROXY_START_PORT is not set (REQUIRED)")
	}

	kubeContext := os.Getenv("KUBE_CONTEXT")
	if kubeContext == "" {
		kubeContext = "local-test"
	}

	proxy, err := postgresql.NewPostgresProxy(kubeContext)
	if err != nil {
		log.Fatalf("Failed to create PostgreSQL proxy: %v", err)
	}

	postgresProxy = proxy

	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, shutting down PostgreSQL proxy")
			proxy.Stop()
			return
		default:
			port, err := strconv.Atoi(startPort)
			if err != nil {
				log.Fatalf("Failed to convert start port to int: %v", err)
			}
			proxy.Start(port, "", "")
		}
	}()
}

func isAtLeastOneProxyRunning() bool {
	return postgresProxy != nil
}

func main() {
	zcontext := context.Background()
	// Setup health check endpoints (!!!CURRENTLY NOT USED!!!)
	setupHealthChecks()
	wg := sync.WaitGroup{}

	// start postgres proxy
	startPostgresProxy(zcontext, &wg)

	// start mongodb proxy
	// TODO: add mongodb proxy

	// start mysql proxy
	// TODO: add mysql proxy

	// start redis proxy
	// TODO: add redis proxy

	// start kafka proxy
	// TODO: add kafka proxy

	// start another proxy
	// TODO: add another proxy

	// if at least one proxy is running, mark as ready or error out
	if !isAtLeastOneProxyRunning() {
		log.Fatal("No proxies running")
	}

	// Wait for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	wg.Wait()

	// Mark as not ready and unhealthy during shutdown
	isReady.Store(false)
	isHealthy.Store(false)

	log.Println("Shutting down...")
}
