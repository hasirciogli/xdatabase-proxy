package postgresql

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/hasirciogli/xdatabase-proxy/pkg/kubernetes"
)

// PostgresProxy implements the DatabaseProxy interface for PostgreSQL
type PostgresProxy struct {
	k8sClient  *kubernetes.K8sClient
	services   []kubernetes.ServiceInfo
	servicesMu sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
}

// StartupParameters contains PostgreSQL startup message parameters
type StartupParameters struct {
	ProtocolVersion uint32
	Parameters      map[string]string
	RawMessage      []byte
}

// ErrorResponse represents a PostgreSQL error response
type ErrorResponse struct {
	Severity string
	Code     string
	Message  string
}

// NewPostgresProxy creates a new PostgreSQL proxy
func NewPostgresProxy(listenPort int, contextName string) (*PostgresProxy, error) {
	// Create a new Kubernetes client with specific context
	if contextName == "" {
		contextName = "default"
	}

	k8sClient, err := kubernetes.NewK8sClient(contextName)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &PostgresProxy{
		k8sClient: k8sClient,
		services:  make([]kubernetes.ServiceInfo, 0),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Register callback for service updates
	k8sClient.RegisterCallback(func(services []kubernetes.ServiceInfo) {
		p.updateServices(services)
	})

	// Start watching for services
	if err := k8sClient.StartPolling(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start service polling: %v", err)
	}

	return p, nil
}

func (p *PostgresProxy) updateServices(services []kubernetes.ServiceInfo) {
	p.servicesMu.Lock()
	defer p.servicesMu.Unlock()

	p.services = services
	log.Printf("Updated services: found %d services", len(services))
	for _, svc := range services {
		log.Printf("Service: %s/%s (deployment: %s, pooled: %v)",
			svc.Namespace, svc.Name, svc.DeploymentID, svc.PooledConnection)
	}
}

func (p *PostgresProxy) findService(deploymentID string, usePool bool) (*kubernetes.ServiceInfo, bool) {
	p.servicesMu.RLock()
	defer p.servicesMu.RUnlock()

	var fallbackService *kubernetes.ServiceInfo

	// First try to find a service matching the connection pool preference
	for i := range p.services {
		svc := &p.services[i]
		if svc.DeploymentID == deploymentID {
			if svc.PooledConnection == usePool {
				return svc, true
			}
			fallbackService = svc
		}
	}

	// Return fallback service if found
	if fallbackService != nil {
		return fallbackService, true
	}

	return nil, false
}

func (p *PostgresProxy) validateAndModifyUsername(params *StartupParameters) (*kubernetes.ServiceInfo, bool, *ErrorResponse) {
	username, exists := params.Parameters["user"]
	if !exists {
		return nil, false, &ErrorResponse{
			Severity: "FATAL",
			Code:     "28000",
			Message:  "no username provided",
		}
	}

	// Split username parts
	parts := strings.Split(username, ".")
	if len(parts) < 2 || parts[0] == "" {
		return nil, false, &ErrorResponse{
			Severity: "FATAL",
			Code:     "28000",
			Message:  "invalid username format: must be in format 'username.deployment_id[.pool]'",
		}
	}

	// Get the base username and deployment ID
	baseUsername := parts[0]
	deploymentID := parts[1]

	// Check if pooled connection is requested based on .pool suffix
	usePool := false
	if len(parts) > 2 && parts[2] == "pool" {
		usePool = true
		// Remove .pool suffix from deployment ID
		deploymentID = parts[1]
	}

	// Find appropriate service for this deployment
	svc, exists := p.findService(deploymentID, usePool)
	if !exists {
		var msg string
		if usePool {
			msg = fmt.Sprintf("no pooled connection service found for deployment %s", deploymentID)
		} else {
			msg = fmt.Sprintf("no direct connection service found for deployment %s", deploymentID)
		}
		return nil, false, &ErrorResponse{
			Severity: "FATAL",
			Code:     "28000",
			Message:  msg,
		}
	}

	// Strip deployment ID and pool suffix from username
	params.Parameters["user"] = baseUsername
	p.rebuildStartupMessage(params)

	if os.Getenv("MODE") != "production" {
		log.Printf("Routing connection for deployment %s to %s:%d (pooled: %v)",
			deploymentID, svc.ClusterIP, svc.Port, svc.PooledConnection)
	}
	return svc, true, nil
}

func (p *PostgresProxy) rebuildStartupMessage(params *StartupParameters) {
	// Calculate total length needed
	totalLength := 4 + 4 // Length field + protocol version

	// Add space for parameters (key + null + value + null)
	for key, value := range params.Parameters {
		totalLength += len(key) + 1 + len(value) + 1
	}
	totalLength++ // Final null byte

	// Create new message buffer
	newMessage := make([]byte, totalLength)

	// Write length (including itself)
	binary.BigEndian.PutUint32(newMessage[0:4], uint32(totalLength))

	// Write protocol version
	binary.BigEndian.PutUint32(newMessage[4:8], params.ProtocolVersion)

	// Write parameters
	offset := 8
	for key, value := range params.Parameters {
		// Write key
		copy(newMessage[offset:], key)
		offset += len(key)
		newMessage[offset] = 0
		offset++

		// Write value
		copy(newMessage[offset:], value)
		offset += len(value)
		newMessage[offset] = 0
		offset++
	}

	// Add final null byte
	newMessage[offset] = 0

	// Update raw message
	params.RawMessage = newMessage
}

func (p *PostgresProxy) sendErrorResponse(conn net.Conn, errResp *ErrorResponse) error {
	// Error message format:
	// 'E' [int32 length] [string fields] \0
	msg := []byte{
		'E',        // Error message type
		0, 0, 0, 0, // Length placeholder
		'S', // Severity
	}
	msg = append(msg, []byte(errResp.Severity)...)
	msg = append(msg, 0)
	msg = append(msg, 'C') // Code
	msg = append(msg, []byte(errResp.Code)...)
	msg = append(msg, 0)
	msg = append(msg, 'M') // Message
	msg = append(msg, []byte(errResp.Message)...)
	msg = append(msg, 0, 0) // Two null terminators

	// Update message length
	binary.BigEndian.PutUint32(msg[1:5], uint32(len(msg)-1))

	_, writeErr := conn.Write(msg)
	return writeErr
}

func (p *PostgresProxy) Start(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("error starting listener: %v", err)
	}

	log.Printf("PostgreSQL proxy listening on :%d", port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go p.HandleConnection(conn)
	}
}

func (p *PostgresProxy) HandleConnection(conn net.Conn) {
	defer conn.Close()

	// Parse startup message
	startupMsg, err := p.parseStartupMessage(conn)
	if err != nil {
		log.Printf("Error parsing startup message: %v\n", err)
		return
	}

	// Print connection information
	p.printStartupInfo(startupMsg)

	// Validate and modify username
	svc, ok, errResp := p.validateAndModifyUsername(startupMsg)
	if !ok {
		log.Printf("Username validation failed: %s\n", errResp.Message)
		if err := p.sendErrorResponse(conn, errResp); err != nil {
			log.Printf("Error sending error response: %v\n", err)
		}
		return
	}
	// Forward connection to real PostgreSQL server
	if err := p.forwardConnection(conn, startupMsg, svc); err != nil {
		log.Printf("Error forwarding connection: %v\n", err)
		return
	}
}

func (p *PostgresProxy) parseStartupMessage(conn net.Conn) (*StartupParameters, error) {
	// Read length (first 4 bytes)
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("error reading length: %v", err)
	}

	// Length includes itself, so subtract 4
	length := binary.BigEndian.Uint32(lengthBuf) - 4

	// Read the rest of the startup message
	messageBuf := make([]byte, length)
	if _, err := io.ReadFull(conn, messageBuf); err != nil {
		return nil, fmt.Errorf("error reading message: %v", err)
	}

	// Parse startup parameters
	params := &StartupParameters{
		ProtocolVersion: binary.BigEndian.Uint32(messageBuf[:4]),
		Parameters:      make(map[string]string),
		RawMessage:      append(lengthBuf, messageBuf...),
	}

	// Parse parameters
	parameters := messageBuf[4:]
	currentPos := 0
	for currentPos < len(parameters) {
		// Find the key
		keyEnd := currentPos
		for keyEnd < len(parameters) && parameters[keyEnd] != 0 {
			keyEnd++
		}
		if keyEnd >= len(parameters) {
			break
		}
		key := string(parameters[currentPos:keyEnd])
		currentPos = keyEnd + 1

		// Find the value
		valueEnd := currentPos
		for valueEnd < len(parameters) && parameters[valueEnd] != 0 {
			valueEnd++
		}
		if valueEnd >= len(parameters) {
			break
		}
		value := string(parameters[currentPos:valueEnd])
		currentPos = valueEnd + 1

		if key != "" {
			// Check if value contains query parameters
			if strings.Contains(value, "?") {
				parts := strings.SplitN(value, "?", 2)
				baseValue := parts[0]
				queryStr := parts[1]

				// Store base value
				params.Parameters[key] = baseValue

				// Parse and store query parameters
				queryParams := strings.Split(queryStr, "&")
				for _, param := range queryParams {
					if param == "" {
						continue
					}
					keyVal := strings.SplitN(param, "=", 2)
					if len(keyVal) == 2 {
						params.Parameters[keyVal[0]] = keyVal[1]
					}
				}
			} else {
				params.Parameters[key] = value
			}
		}
	}

	return params, nil
}

func (p *PostgresProxy) printStartupInfo(params *StartupParameters) {
	if os.Getenv("MODE") != "production" {
		return
	}

	log.Printf("=== PostgreSQL Connection Info ===")

	// Print main connection parameters
	if user, ok := params.Parameters["user"]; ok {
		log.Printf("  → Username: %s", user)
	}
	if db, ok := params.Parameters["database"]; ok {
		log.Printf("  → Database: %s", db)
	}
	if app, ok := params.Parameters["application_name"]; ok {
		log.Printf("  → Application: %s", app)
	}

	// Print all other parameters except main ones
	var otherParams []string
	for key, value := range params.Parameters {
		// Skip main parameters that are already printed
		if key == "user" || key == "database" || key == "application_name" {
			continue
		}
		otherParams = append(otherParams, fmt.Sprintf("%s=%s", key, value))
	}

	if len(otherParams) > 0 {
		log.Printf("  → Connection Parameters:")
		for _, param := range otherParams {
			log.Printf("    • %s", param)
		}
	}

	log.Printf("===============================")
}

func (p *PostgresProxy) forwardConnection(clientConn net.Conn, startupMsg *StartupParameters, service *kubernetes.ServiceInfo) error {
	// Connect to the real PostgreSQL server
	backendConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", service.ClusterDNS, service.Port))
	if err != nil {
		return fmt.Errorf("error connecting to backend: %v", err)
	}
	defer backendConn.Close()

	// Forward the startup message
	if _, err := backendConn.Write(startupMsg.RawMessage); err != nil {
		return fmt.Errorf("error forwarding startup message: %v", err)
	}

	// Start forwarding in both directions
	go func() {
		io.Copy(backendConn, clientConn)
	}()
	io.Copy(clientConn, backendConn)

	return nil
}

func (p *PostgresProxy) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	if p.k8sClient != nil {
		p.k8sClient.Stop()
	}
}
