package postgresql

import (
	"bytes" // Buffer kullanmak için eklendi
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors" // Hata kontrolü için eklendi
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hasirciogli/xdatabase-proxy/pkg/kubernetes"
)

const (
	sslRequestCode    = 80877103 // 12345679 in decimal
	cancelRequestCode = 80877102 // 12345678 in decimal
)

// PostgresProxy implements the DatabaseProxy interface for PostgreSQL
type PostgresProxy struct {
	k8sClient  *kubernetes.K8sClient
	services   []kubernetes.ServiceInfo
	servicesMu sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	tlsConfig  *tls.Config // TLS yapılandırmasını saklamak için eklendi
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
func NewPostgresProxy(contextName string) (*PostgresProxy, error) {
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
		// tlsConfig başlangıçta nil olacak, Start içinde ayarlanacak
	}

	k8sClient.RegisterCallback(func(services []kubernetes.ServiceInfo) {
		p.updateServices(services)
	})

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
	// Gereksiz detaylı log kaldırıldı
}

func (p *PostgresProxy) findService(deploymentID string, usePool bool) (*kubernetes.ServiceInfo, bool) {
	p.servicesMu.RLock()
	defer p.servicesMu.RUnlock()

	var fallbackService *kubernetes.ServiceInfo
	var matchingServices []*kubernetes.ServiceInfo

	// İlk taramada uygun servisleri topla
	for i := range p.services {
		svc := &p.services[i]
		if svc.DeploymentID == deploymentID {
			if svc.PooledConnection == usePool {
				matchingServices = append(matchingServices, svc)
			}
			// Her durumda bir fallback servisi sakla
			if fallbackService == nil {
				fallbackService = svc
			}
		}
	}

	// Eğer birden fazla eşleşen servis bulunduysa, uyarı logla
	if len(matchingServices) > 1 {
		poolStatus := "unpooled"
		if usePool {
			poolStatus = "pooled"
		}

		serviceNames := make([]string, len(matchingServices))
		for i, svc := range matchingServices {
			serviceNames[i] = fmt.Sprintf("%s/%s", svc.Namespace, svc.Name)
		}

		log.Printf("WARNING: Multiple %s services found for deployment '%s': %s - using first one: %s/%s",
			poolStatus, deploymentID, strings.Join(serviceNames, ", "),
			matchingServices[0].Namespace, matchingServices[0].Name)

		return matchingServices[0], true
	}

	// Tam olarak bir eşleşen servis bulunduysa
	if len(matchingServices) == 1 {
		return matchingServices[0], true
	}

	// Eşleşen servis bulunamadı, fallback varsa onu kullan
	if fallbackService != nil {
		poolStatus := "pooled"
		if !usePool {
			poolStatus = "unpooled"
		}

		log.Printf("No exact %s service match for deployment '%s', using fallback service: %s/%s (pooled: %v)",
			poolStatus, deploymentID,
			fallbackService.Namespace, fallbackService.Name, fallbackService.PooledConnection)
		return fallbackService, true
	}

	// Hiçbir uygun servis bulunamadı
	return nil, false
}

func (p *PostgresProxy) validateAndModifyUsername(params *StartupParameters) (*kubernetes.ServiceInfo, bool, *ErrorResponse) {
	username, exists := params.Parameters["user"]
	if !exists {
		return nil, false, &ErrorResponse{Severity: "FATAL", Code: "28000", Message: "no username provided"}
	}

	parts := strings.Split(username, ".")
	if len(parts) < 2 || parts[0] == "" {
		return nil, false, &ErrorResponse{Severity: "FATAL", Code: "28000", Message: fmt.Sprintf("invalid username format: must be 'username.deployment_id[.pool]', got '%s'", username)}
	}

	baseUsername := parts[0]
	deploymentID := parts[1]
	usePool := false
	if len(parts) > 2 && parts[2] == "pool" {
		usePool = true
	}

	svc, exists := p.findService(deploymentID, usePool)
	if !exists {
		errMsg := fmt.Sprintf("no service found for deployment '%s'", deploymentID)
		if usePool {
			errMsg = fmt.Sprintf("no pooled service found for deployment '%s'", deploymentID)
		}
		return nil, false, &ErrorResponse{Severity: "FATAL", Code: "08001", Message: errMsg}
	}

	// Kullanıcı adını backend için güncelle
	params.Parameters["user"] = baseUsername
	p.rebuildStartupMessage(params) // Startup mesajını yeniden oluştur

	log.Printf("Routing connection for deployment '%s' (user: %s) to %s/%s (%s:%d, pooled: %v)",
		deploymentID, baseUsername, svc.Namespace, svc.Name, svc.ClusterIP, svc.Port, svc.PooledConnection)

	return svc, true, nil
}

func (p *PostgresProxy) rebuildStartupMessage(params *StartupParameters) {
	// Calculate total length needed
	totalLength := 4 + 4 // Length field + protocol version
	for key, value := range params.Parameters {
		totalLength += len(key) + 1 + len(value) + 1
	}
	totalLength++ // Final null byte

	newMessage := make([]byte, totalLength)
	binary.BigEndian.PutUint32(newMessage[0:4], uint32(totalLength))
	binary.BigEndian.PutUint32(newMessage[4:8], params.ProtocolVersion)

	offset := 8
	for key, value := range params.Parameters {
		copy(newMessage[offset:], key)
		offset += len(key)
		newMessage[offset] = 0
		offset++
		copy(newMessage[offset:], value)
		offset += len(value)
		newMessage[offset] = 0
		offset++
	}
	newMessage[offset] = 0
	params.RawMessage = newMessage
}

func (p *PostgresProxy) sendErrorResponse(conn net.Conn, errResp *ErrorResponse) error {
	var msgData []byte
	msgData = append(msgData, 'S')
	msgData = append(msgData, []byte(errResp.Severity)...)
	msgData = append(msgData, 0)
	msgData = append(msgData, 'C')
	msgData = append(msgData, []byte(errResp.Code)...)
	msgData = append(msgData, 0)
	msgData = append(msgData, 'M')
	msgData = append(msgData, []byte(errResp.Message)...)
	msgData = append(msgData, 0)
	msgData = append(msgData, 0) // Final null terminator

	msg := make([]byte, 1+4+len(msgData))
	msg[0] = 'E'
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(msgData)))
	copy(msg[5:], msgData)

	_, writeErr := conn.Write(msg)
	if writeErr != nil {
		log.Printf("Error sending error response to %s: %v", conn.RemoteAddr(), writeErr)
	} else {
		log.Printf("Sent error response to %s: Sev=%s Code=%s Msg=%s", conn.RemoteAddr(), errResp.Severity, errResp.Code, errResp.Message)
	}
	return writeErr
}

// generateSelfSignedCert generates a self-signed certificate and key pair
func generateSelfSignedCert(p *PostgresProxy) (certPEM, keyPEM []byte, err error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"PostgreSQL Proxy"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	// Encode private key to PEM
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Sertifika ve anahtarı kubernetese'ye kaydet
	err = p.k8sClient.UpsertSecret(os.Getenv("NAMESPACE"), "self-signed-cert", map[string][]byte{
		"tls.crt": certPEM,
		"tls.key": keyPEM,
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to create secret: %v", err)
	}
	return certPEM, keyPEM, nil
}

func getSelfCertsFromK8s(p *PostgresProxy) (certPEM, keyPEM []byte, err error) {
	// Kubernetes'ten sertifikayı almaya çalış
	secret, err := p.k8sClient.GetSecret(os.Getenv("NAMESPACE"), "self-signed-cert")
	if err != nil {
		// Sertifika bulunamadıysa, yeni bir tane oluştur
		log.Printf("Kubernetes'te sertifika bulunamadı, yeni bir tane oluşturuluyor: %v", err)
		return generateSelfSignedCert(p)
	}

	// Sertifika ve anahtarı al
	certPEM = secret.Data["tls.crt"]
	keyPEM = secret.Data["tls.key"]

	// Sertifikanın geçerlilik süresini kontrol et
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Printf("Geçersiz sertifika formatı, yeni bir tane oluşturuluyor")
		return generateSelfSignedCert(p)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("Sertifika ayrıştırılamadı, yeni bir tane oluşturuluyor: %v", err)
		return generateSelfSignedCert(p)
	}

	// Sertifikanın son kullanma tarihini kontrol et
	if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
		log.Printf("Sertifika süresi dolmuş veya henüz geçerli değil, yeni bir tane oluşturuluyor")
		return generateSelfSignedCert(p)
	}

	return certPEM, keyPEM, nil
}

// Start initiates the proxy listener. Always starts a plain TCP listener.
// If certFile and keyFile are provided, TLS capability is enabled for connections that request it.
// If no cert files are provided, a self-signed certificate will be automatically generated and
// stored in Kubernetes (not written to local disk).
func (p *PostgresProxy) Start(port int, certFile, keyFile string) error {
	listenAddr := fmt.Sprintf(":%d", port)

	if certFile != "" && keyFile != "" {
		cert, errLoad := tls.LoadX509KeyPair(certFile, keyFile)
		if errLoad != nil {
			return fmt.Errorf("error loading TLS key pair from %s and %s: %v", certFile, keyFile, errLoad)
		}
		p.tlsConfig = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
			ClientAuth:         tls.NoClientCert,
			ServerName:         "localhost",
		}
		log.Printf("TLS enabled with certificate files")
	} else {
		certPEM, keyPEM, err := getSelfCertsFromK8s(p)
		if err != nil {
			return fmt.Errorf("failed to get self-signed certificate: %v", err)
		}

		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("error creating TLS key pair from PEM data: %v", err)
		}

		p.tlsConfig = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
			ClientAuth:         tls.NoClientCert,
			ServerName:         "localhost",
		}
		log.Printf("TLS enabled with auto-generated certificate")
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("error starting TCP listener on %s: %v", listenAddr, err)
	}
	log.Printf("PostgreSQL proxy listening on %s", listenAddr)

	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				log.Println("Listener stopped.")
				return nil
			default:
				log.Printf("Error accepting connection: %v", err)
				continue
			}
		}
		go p.HandleConnection(conn)
	}
}

// HandleConnection processes an incoming client connection, determining if TLS is needed.
func (p *PostgresProxy) HandleConnection(initialConn net.Conn) {
	defer initialConn.Close()

	// Gereksiz "Handling new connection" log kaldırıldı

	initialBytes := make([]byte, 8)
	_, err := io.ReadFull(initialConn, initialBytes)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			log.Printf("Connection closed prematurely: %v", err)
		} else {
			log.Printf("Error reading initial bytes: %v", err)
		}
		return
	}

	length := binary.BigEndian.Uint32(initialBytes[0:4])
	requestCode := binary.BigEndian.Uint32(initialBytes[4:8])

	var conn net.Conn = initialConn
	var startupMessageReader io.Reader

	if length == 8 && requestCode == sslRequestCode {
		// Gereksiz "Received SSLRequest" log kaldırıldı
		if p.tlsConfig != nil {
			if _, err := conn.Write([]byte{'S'}); err != nil {
				log.Printf("Error sending SSL response: %v", err)
				return
			}
			// Gereksiz "Performing TLS handshake" log kaldırıldı
			// Gereksiz "Using tls.Config with ServerName" log kaldırıldı
			tlsConn := tls.Server(conn, p.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("TLS handshake failed: %v", err)
				_ = p.sendErrorResponse(conn, &ErrorResponse{
					Severity: "FATAL",
					Code:     "08006",
					Message:  fmt.Sprintf("TLS handshake failed: %v", err),
				})
				return
			}
			// Gereksiz "TLS handshake successful" log kaldırıldı
			conn = tlsConn
			startupMessageReader = conn
		} else {
			// Gereksiz "TLS is not configured" log kaldırıldı
			_, _ = conn.Write([]byte{'N'})
			return
		}
	} else {
		// Gereksiz "No SSLRequest received" log kaldırıldı
		remainingLength := 0
		if length > 8 {
			remainingLength = int(length) - 8
		} else if length == 8 && requestCode == cancelRequestCode {
			// Gereksiz "Received possible CancelRequest" log kaldırıldı
			return
		} else if length < 8 {
			log.Printf("Invalid message length: %d", length)
			return
		}

		fullMessageReader := io.MultiReader(
			bytes.NewReader(initialBytes),
			io.LimitReader(conn, int64(remainingLength)),
		)
		startupMessageReader = fullMessageReader
	}

	// Gereksiz "Proceeding to parse StartupMessage" log kaldırıldı
	startupMsg, err := p.parseStartupMessage(startupMessageReader)
	if err != nil {
		log.Printf("Error parsing startup message: %v", err)
		return
	}

	// Gereksiz detaylı startup bilgisi loglaması
	p.printStartupInfo(startupMsg)

	svc, ok, errResp := p.validateAndModifyUsername(startupMsg)
	if !ok {
		log.Printf("Username validation failed: %s", errResp.Message)
		if sendErr := p.sendErrorResponse(conn, errResp); sendErr != nil {
			log.Printf("Error sending validation error response: %v", sendErr)
		}
		return
	}

	if err := p.forwardConnection(conn, startupMsg, svc); err != nil {
		log.Printf("Error forwarding connection: %v", err)
		_ = p.sendErrorResponse(conn, &ErrorResponse{
			Severity: "FATAL",
			Code:     "08001",
			Message:  fmt.Sprintf("failed to connect to backend service %s/%s: %v", svc.Namespace, svc.Name, err),
		})
		return
	}

	// Gereksiz "Connection handling finished" log kaldırıldı
}

// parseStartupMessage reads and parses the PostgreSQL startup message from the given reader.
// Assumes the reader provides the complete startup message (length included).
// It no longer needs to handle SSLRequest itself.
func (p *PostgresProxy) parseStartupMessage(r io.Reader) (*StartupParameters, error) {
	// İlk 4 byte (uzunluk)
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lengthBuf); err != nil {
		return nil, fmt.Errorf("error reading startup message length: %w", err)
	}
	length := binary.BigEndian.Uint32(lengthBuf)

	// Minimum uzunluk 8 (length + protocol/request code)
	// Ancak parametreler olacağı için genellikle daha büyüktür.
	if length < 8 {
		return nil, fmt.Errorf("invalid startup message length: %d", length)
	}

	// Mesajın geri kalanını oku (length - 4 byte)
	messageBody := make([]byte, length-4)
	if _, err := io.ReadFull(r, messageBody); err != nil {
		return nil, fmt.Errorf("error reading startup message body: %w", err)
	}

	// Protokol versiyonu (ilk 4 byte)
	protocolVersion := binary.BigEndian.Uint32(messageBody[0:4])

	// CancelRequest kontrolü (burada da gelebilir ama HandleConnection'da da bakılıyor)
	if length == 8 && protocolVersion == cancelRequestCode {
		return nil, errors.New("received CancelRequest instead of StartupMessage")
	}
	// Teorik olarak SSLRequest buraya gelmemeli ama kontrol edelim
	if length == 8 && protocolVersion == sslRequestCode {
		return nil, errors.New("received unexpected SSLRequest after initial check")
	}

	// Protokol 3.0 kontrolü (opsiyonel)
	if protocolVersion != 196608 { // 3.0 = 196608
		log.Printf("Warning: Received connection with potentially unsupported PostgreSQL protocol version %d (expected 196608)", protocolVersion)
	}

	params := &StartupParameters{
		ProtocolVersion: protocolVersion,
		Parameters:      make(map[string]string),
		// RawMessage: lengthBuf + messageBody
		RawMessage: append(lengthBuf, messageBody...),
	}

	// Parametreleri ayrıştır (protokol versiyonundan sonraki kısım: messageBody[4:])
	parametersData := messageBody[4:]
	currentPos := 0
	for currentPos < len(parametersData) {
		if parametersData[currentPos] == 0 { // Sonlandırıcı null byte
			break
		}
		keyStart := currentPos
		keyEnd := bytes.IndexByte(parametersData[currentPos:], 0)
		if keyEnd == -1 {
			return nil, errors.New("malformed startup packet: parameter key not null-terminated")
		}
		keyEnd += currentPos // İndeksi tam diziye göre ayarla
		key := string(parametersData[keyStart:keyEnd])
		currentPos = keyEnd + 1

		if currentPos >= len(parametersData) {
			// Anahtar var ama değer için yer kalmadı (hatalı paket)
			return nil, errors.New("malformed startup packet: missing value after key")
		}

		valueStart := currentPos
		valueEnd := bytes.IndexByte(parametersData[currentPos:], 0)
		if valueEnd == -1 {
			return nil, errors.New("malformed startup packet: parameter value not null-terminated")
		}
		valueEnd += currentPos // İndeksi tam diziye göre ayarla
		value := string(parametersData[valueStart:valueEnd])
		currentPos = valueEnd + 1

		if key != "" {
			params.Parameters[key] = value
		}
	}

	return params, nil
}

func (p *PostgresProxy) printStartupInfo(params *StartupParameters) {
	// Tüm detaylı loglamalar kaldırıldı, sadece kritik bilgiler korundu
	if user, ok := params.Parameters["user"]; ok {
		log.Printf("Connection requested by user: %s", user)
	}
}

// forwardConnection establishes a plain TCP connection to the backend and proxies data.
// clientConn can be either net.Conn or tls.Conn. Backend connection is always net.Conn.
func (p *PostgresProxy) forwardConnection(clientConn net.Conn, startupMsg *StartupParameters, service *kubernetes.ServiceInfo) error {
	backendAddr := fmt.Sprintf("%s:%d", service.ClusterDNS, service.Port)

	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		return fmt.Errorf("error connecting to backend %s: %v", backendAddr, err)
	}
	defer backendConn.Close()

	if _, err := backendConn.Write(startupMsg.RawMessage); err != nil {
		return fmt.Errorf("error forwarding modified startup message to backend %s: %v", backendAddr, err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	clientDesc := fmt.Sprintf("client %s", clientConn.RemoteAddr())
	backendDesc := fmt.Sprintf("backend %s", backendAddr)

	copyData := func(dst net.Conn, src net.Conn, srcDesc, dstDesc string) {
		defer wg.Done()
		defer func() {
			if tcpConn, ok := dst.(*net.TCPConn); ok {
				_ = tcpConn.CloseWrite()
			} else if tlsConn, ok := dst.(*tls.Conn); ok {
				_ = tlsConn.CloseWrite()
			} else {
				_ = dst.Close()
			}
			// Gereksiz log kaldırıldı
		}()

		_, err := io.Copy(dst, src)
		// Gereksiz detaylı byte log kaldırıldı
		if err != nil {
			netErr, isNetErr := err.(net.Error)
			if err != io.EOF && (!isNetErr || !netErr.Timeout()) && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("Error during data transfer: %v", err)
			}
		}
	}

	go copyData(backendConn, clientConn, clientDesc, backendDesc)
	go copyData(clientConn, backendConn, backendDesc, clientDesc)

	wg.Wait()
	// Gereksiz log kaldırıldı
	return nil
}

// Stop signals the proxy to shut down gracefully.
func (p *PostgresProxy) Stop() {
	log.Println("Stopping PostgreSQL proxy...")
	if p.cancel != nil {
		p.cancel() // Accept döngüsünü durdurmak için context'i iptal et
	}
	if p.k8sClient != nil {
		p.k8sClient.Stop()
	}
	// Listener, Start fonksiyonundaki defer ile kapatılacak.
	log.Println("PostgreSQL proxy stopped.")
}
