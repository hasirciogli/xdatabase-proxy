// main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/hasirciogli/xdatabase-proxy/pkg/kubernetes"
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

	// Create a new Kubernetes client with specific context
	contextName := os.Getenv("KUBE_CONTEXT")
	if contextName == "" {
		contextName = "local-test"
	}

	k8sClient, err := kubernetes.NewK8sClient(contextName)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}
	defer k8sClient.Stop()

	fmt.Printf("Using Kubernetes context: %s\n", contextName)

	// Start watching for services
	if err := k8sClient.WatchDatabaseServices(context.Background(), func(services []kubernetes.ServiceInfo) {
		for _, svc := range services {
			log.Printf("Service Info: Name=%s, Namespace=%s, DB Type=%s, PooledConnection=%v, ClusterDNS=%s",
				svc.Name, svc.Namespace, svc.DatabaseType, svc.PooledConnection, svc.ClusterDNS)
		}
		// Mark as ready once we've successfully started watching services
		isReady.Store(true)
	}); err != nil {
		log.Fatalf("Failed to start watching: %v", err)
	}

	fmt.Println("Watching for services...")

	// Wait for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	// Mark as not ready and unhealthy during shutdown
	isReady.Store(false)
	isHealthy.Store(false)

	log.Println("Shutting down...")
}
