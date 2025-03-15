// main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/hasirciogli/xdatabase-proxy/pkg/kubernetes"
)

// func main() {
// 	// Create proxies
// 	postgresProxy := postgresql.NewPostgresProxy(3001, "localhost", 5432)
// 	mysqlProxy := mysql.NewMySQLProxy(3002, "localhost", 3306)
// 	mongoProxy := mongodb.NewMongoDBProxy(3003, "localhost", 27017)

// 	// Start PostgreSQL proxy
// 	go func() {
// 		if err := postgresProxy.Start(postgresProxy.ListenPort); err != nil {
// 			log.Printf("PostgreSQL proxy error: %v", err)
// 		}
// 	}()

// 	// Start MySQL proxy
// 	go func() {
// 		if err := mysqlProxy.Start(mysqlProxy.ListenPort); err != nil {
// 			log.Printf("MySQL proxy error: %v", err)
// 		}
// 	}()

// 	// Start MongoDB proxy
// 	if err := mongoProxy.Start(mongoProxy.ListenPort); err != nil {
// 		log.Printf("MongoDB proxy error: %v", err)
// 	}
// }

// sadece postgres proxy
func main() {
	// Create a new Kubernetes client with specific context
	contextName := os.Getenv("KUBE_CONTEXT") // Take context name from environment variable
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
	}); err != nil {
		log.Fatalf("Failed to start watching: %v", err)
	}

	fmt.Println("Watching for services...")

	// Wait for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
}
