package kubernetes

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type ServiceInfo struct {
	Name             string
	Namespace        string
	DeploymentID     string
	ClusterIP        string
	ClusterDNS       string
	Port             int32
	DatabaseType     string
	PooledConnection bool
}

type K8sClient struct {
	clientset    *kubernetes.Clientset
	services     []ServiceInfo
	servicesMu   sync.RWMutex
	pollInterval time.Duration
	ctx          context.Context
	cancel       context.CancelFunc
	callbacks    []func([]ServiceInfo)
	callbacksMu  sync.RWMutex
}

func NewK8sClient(contextName string) (*K8sClient, error) {
	var config *rest.Config
	var err error

	if contextName == "" {
		contextName = "default"
	}

	// Try in-cluster config first
	config, err = rest.InClusterConfig()
	if err != nil {
		// Fallback to kubeconfig
		kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")

		// Create config with specific context
		configOverrides := &clientcmd.ConfigOverrides{
			CurrentContext: contextName,
		}
		loadingRules := &clientcmd.ClientConfigLoadingRules{
			ExplicitPath: kubeconfig,
		}

		clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			loadingRules,
			configOverrides,
		)

		config, err = clientConfig.ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create k8s config: %v", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &K8sClient{
		clientset:    clientset,
		services:     make([]ServiceInfo, 0),
		pollInterval: 30 * time.Second, // Default poll interval
		ctx:          ctx,
		cancel:       cancel,
	}, nil
}

func (k *K8sClient) SetPollInterval(interval time.Duration) {
	k.pollInterval = interval
}

func (k *K8sClient) RegisterCallback(callback func([]ServiceInfo)) {
	k.callbacksMu.Lock()
	defer k.callbacksMu.Unlock()
	k.callbacks = append(k.callbacks, callback)
}

func (k *K8sClient) notifyCallbacks() {
	k.servicesMu.RLock()
	services := make([]ServiceInfo, len(k.services))
	copy(services, k.services)
	k.servicesMu.RUnlock()

	k.callbacksMu.RLock()
	callbacks := make([]func([]ServiceInfo), len(k.callbacks))
	copy(callbacks, k.callbacks)
	k.callbacksMu.RUnlock()

	for _, callback := range callbacks {
		callback(services)
	}
}

func (k *K8sClient) pollServices() error {
	services, err := k.DiscoverDatabaseServices()
	if err != nil {
		return err
	}

	k.servicesMu.Lock()
	k.services = services
	k.servicesMu.Unlock()

	k.notifyCallbacks()
	return nil
}

func (k *K8sClient) StartPolling() error {
	// Initial discovery
	if err := k.pollServices(); err != nil {
		return err
	}

	// Start watching for changes
	go k.watchServices()

	return nil
}

func (k *K8sClient) watchServices() {
	for {
		select {
		case <-k.ctx.Done():
			return
		default:
			watch, err := k.clientset.CoreV1().Services("").Watch(k.ctx, metav1.ListOptions{
				LabelSelector: "xdatabase-proxy-enabled=true",
			})
			if err != nil {
				log.Printf("Error watching services: %v, retrying in 5 seconds", err)
				time.Sleep(5 * time.Second)
				continue
			}

			for event := range watch.ResultChan() {
				if k.ctx.Err() != nil {
					watch.Stop()
					return
				}

				switch event.Type {
				case "ADDED", "MODIFIED", "DELETED":
					if err := k.pollServices(); err != nil {
						log.Printf("Error polling services after watch event: %v", err)
					}
				}
			}
		}
	}
}

func (k *K8sClient) Stop() {
	k.cancel()
}

func (k *K8sClient) DiscoverDatabaseServices() ([]ServiceInfo, error) {
	var services []ServiceInfo

	// List all services in all namespaces
	svcList, err := k.clientset.CoreV1().Services("").List(context.Background(), metav1.ListOptions{
		LabelSelector: "xdatabase-proxy-enabled=true",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %v", err)
	}

	for _, svc := range svcList.Items {
		// Get deployment ID from label
		deploymentID := svc.Labels["xdatabase-proxy-deployment-id"]
		if deploymentID == "" {
			log.Printf("Warning: Service %s/%s has xdatabase-proxy-enabled=true but no xdatabase-proxy-deployment-id", svc.Namespace, svc.Name)
			continue
		}

		// Get database type from label
		dbType := svc.Labels["xdatabase-proxy-database-type"]
		if dbType == "" {
			log.Printf("Warning: Service %s/%s has no database type specified", svc.Namespace, svc.Name)
			dbType = "postgresql" // Default to postgresql if not specified
		}

		// Get database type from label
		destinationPort := svc.Labels["xdatabase-proxy-destination-port"]
		if destinationPort == "" {
			log.Printf("Warning: Service %s/%s has no destination port specified", svc.Namespace, svc.Name)
			destinationPort = "5432" // Default to postgresql if not specified
		}

		// Get pooled connection status from label
		pooledConnection := false
		if pooledStr := svc.Labels["xdatabase-proxy-pooled"]; pooledStr == "true" {
			pooledConnection = true
		}

		// Find the PostgreSQL port
		port, err := strconv.Atoi(destinationPort)
		if err != nil {
			log.Printf("Warning: Service %s/%s has invalid destination port: %s", svc.Namespace, svc.Name, destinationPort)
			port = 5432
		}

		if port == 0 {
			log.Printf("Warning: Service %s/%s has no PostgreSQL port", svc.Namespace, svc.Name)
			continue
		}

		services = append(services, ServiceInfo{
			Name:             svc.Name,
			Namespace:        svc.Namespace,
			DeploymentID:     deploymentID,
			ClusterIP:        svc.Spec.ClusterIP,
			ClusterDNS:       fmt.Sprintf("%s.%s.svc.cluster.local", svc.Name, svc.Namespace),
			Port:             int32(port),
			DatabaseType:     dbType,
			PooledConnection: pooledConnection,
		})
	}

	return services, nil
}

func (k *K8sClient) WatchDatabaseServices(ctx context.Context, callback func([]ServiceInfo)) error {
	// Initial discovery
	services, err := k.DiscoverDatabaseServices()
	if err != nil {
		return err
	}
	callback(services)

	// Watch for changes
	watch, err := k.clientset.CoreV1().Services("").Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to watch services: %v", err)
	}

	go func() {
		for event := range watch.ResultChan() {
			_, ok := event.Object.(*corev1.Service)
			if !ok {
				continue
			}

			// Rediscover all services on any change
			services, err := k.DiscoverDatabaseServices()
			if err != nil {
				log.Printf("Error rediscovering services: %v", err)
				continue
			}
			callback(services)
		}
	}()

	return nil
}
