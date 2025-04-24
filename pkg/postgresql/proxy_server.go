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
	// Loglama sadeleştirildi
	log.Printf("Updated services: %d services found.", len(services))
}

func (p *PostgresProxy) findService(deploymentID string, usePool bool) (*kubernetes.ServiceInfo, bool) {
	p.servicesMu.RLock()
	defer p.servicesMu.RUnlock()
	var fallbackService *kubernetes.ServiceInfo
	for i := range p.services {
		svc := &p.services[i]
		if svc.DeploymentID == deploymentID {
			if svc.PooledConnection == usePool {
				return svc, true
			}
			fallbackService = svc
		}
	}
	if fallbackService != nil {
		return fallbackService, true
	}
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

	// TLS yapılandırmasını yükle (eğer sertifika dosyaları verilmişse)
	if certFile != "" && keyFile != "" {
		cert, errLoad := tls.LoadX509KeyPair(certFile, keyFile)
		if errLoad != nil {
			return fmt.Errorf("error loading TLS key pair from %s and %s: %v", certFile, keyFile, errLoad)
		}
		p.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			// MinVersion:   tls.VersionTLS12, // Temporarily remove for debugging
			// Add more permissive settings
			InsecureSkipVerify: true,             // Allow self-signed certificates
			ClientAuth:         tls.NoClientCert, // Don't require client certificates
			// Add more hostnames to the certificate
			ServerName: "localhost",
		}
		log.Printf("TLS capability enabled using cert: %s, key: %s", certFile, keyFile)
	} else {
		// Get or generate self-signed certificate from/to Kubernetes
		certPEM, keyPEM, err := getSelfCertsFromK8s(p)
		if err != nil {
			return fmt.Errorf("failed to get self-signed certificate: %v", err)
		}

		// Load certificate directly from memory instead of writing to files
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("error creating TLS key pair from PEM data: %v", err)
		}

		p.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			// MinVersion:   tls.VersionTLS12, // Temporarily remove for debugging
			// Add more permissive settings
			InsecureSkipVerify: true,             // Allow self-signed certificates
			ClientAuth:         tls.NoClientCert, // Don't require client certificates
			// Add more hostnames to the certificate
			ServerName: "localhost",
		}
		log.Printf("TLS capability enabled using auto-generated self-signed certificate stored in Kubernetes")
	}

	// HER ZAMAN plain TCP listener başlatılır
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("error starting TCP listener on %s: %v", listenAddr, err)
	}
	log.Printf("PostgreSQL proxy listening for TCP connections on %s (TLS auto-negotiation)", listenAddr)

	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				log.Println("Listener stopped.")
				return nil // Context iptal edildi, normal duruş
			default:
				// Listener hatası (örn. çok fazla dosya açık)
				log.Printf("Error accepting connection: %v", err)
				// Bu tür hatalar genellikle geçici değildir, belki kısa bir süre bekleyip tekrar denemek veya çıkmak gerekebilir.
				// Şimdilik devam ediyoruz.
				continue
			}
		}
		// Her bağlantıyı ayrı goroutine'de işle
		go p.HandleConnection(conn)
	}
}

// HandleConnection processes an incoming client connection, determining if TLS is needed.
func (p *PostgresProxy) HandleConnection(initialConn net.Conn) {
	defer initialConn.Close() // En başta defer et, her durumda kapanmasını sağla

	remoteAddr := initialConn.RemoteAddr().String()
	log.Printf("Handling new connection from %s", remoteAddr)

	// --- İlk Mesajı Oku ve TLS Gerekip Gerekmediğini Belirle ---
	// İlk 8 byte'ı okuyarak SSLRequest mi yoksa StartupMessage mı olduğunu anla
	initialBytes := make([]byte, 8)
	_, err := io.ReadFull(initialConn, initialBytes)
	if err != nil {
		// Bağlantı 8 byte gönderemeden kapandıysa veya başka bir okuma hatası varsa
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			log.Printf("Connection from %s closed prematurely (before initial 8 bytes): %v", remoteAddr, err)
		} else {
			log.Printf("Error reading initial 8 bytes from %s: %v", remoteAddr, err)
		}
		return // Hata durumunda işlemi bitir
	}
	// n == 8 olmalı, ReadFull bunu garantiler (hata yoksa)

	length := binary.BigEndian.Uint32(initialBytes[0:4])
	requestCode := binary.BigEndian.Uint32(initialBytes[4:8])

	var conn net.Conn = initialConn    // Mevcut bağlantıyı tutacak değişken, TLS olursa güncellenecek
	var startupMessageReader io.Reader // Startup mesajını okumak için kullanılacak reader

	// --- Karar Verme Mekanizması ---
	if length == 8 && requestCode == sslRequestCode {
		// 1. SSLRequest Geldi
		log.Printf("Received SSLRequest from %s", remoteAddr)
		if p.tlsConfig != nil {
			// TLS destekleniyor, 'S' gönder
			if _, err := conn.Write([]byte{'S'}); err != nil {
				log.Printf("Error sending 'S' (SSL Supported) to %s: %v", remoteAddr, err)
				return
			}
			// TLS Handshake'i yap
			log.Printf("Performing TLS handshake with %s...", remoteAddr)
			// Log the ServerName being used
			log.Printf("Using tls.Config with ServerName: %s", p.tlsConfig.ServerName)
			tlsConn := tls.Server(conn, p.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("TLS handshake with %s failed: %v", remoteAddr, err)
				// Try to send error response before closing
				_ = p.sendErrorResponse(conn, &ErrorResponse{
					Severity: "FATAL",
					Code:     "08006", // connection_failure
					Message:  fmt.Sprintf("TLS handshake failed: %v", err),
				})
				return
			}
			log.Printf("TLS handshake with %s successful.", remoteAddr)
			conn = tlsConn // Bağlantıyı TLS bağlantısıyla güncelle
			// Startup mesajı artık bu güvenli bağlantıdan okunacak
			startupMessageReader = conn
		} else {
			// TLS desteklenmiyor, 'N' gönder ve bağlantıyı kapat
			log.Printf("TLS is not configured. Sending 'N' (SSL Not Supported) to %s.", remoteAddr)
			_, _ = conn.Write([]byte{'N'}) // Hata olsa da loglayıp devam et (kapatılacak)
			return                         // Bağlantıyı kapat
		}
	} else {
		// 2. SSLRequest DEĞİL (StartupMessage veya CancelRequest olmalı)
		log.Printf("No SSLRequest received from %s, assuming plaintext or CancelRequest.", remoteAddr)
		// Okunan ilk 8 byte, mesajın başlangıcıdır. Geri kalanını da okuyabilmek için
		// bu 8 byte'ı bir buffer'a koyup, geri kalanını normal bağlantıdan okuyacak
		// bir reader oluşturuyoruz.
		remainingLength := 0
		if length > 8 {
			remainingLength = int(length) - 8
		} else if length == 8 && requestCode == cancelRequestCode {
			// Bu bir CancelRequest olabilir, henüz tam desteklenmiyor.
			log.Printf("Received possible CancelRequest (length=8, code=%d) from %s. Closing connection.", cancelRequestCode, remoteAddr)
			// TODO: CancelRequest işleme eklenebilir (backend process ID ve secret key gerektirir)
			return
		} else if length < 8 {
			log.Printf("Invalid message length %d received from %s. Closing connection.", length, remoteAddr)
			return
		}
		// else: length == 8 ama CancelRequest değilse bu da hatalı bir durumdur.

		// Okunan ilk 8 byte ile geri kalanını birleştirecek reader
		fullMessageReader := io.MultiReader(
			bytes.NewReader(initialBytes),                // Önce okunan 8 byte
			io.LimitReader(conn, int64(remainingLength)), // Sonra geri kalan kısım
		)
		startupMessageReader = fullMessageReader
		// conn değişkeni initialConn (plaintext) olarak kalır.
	}

	// --- TLS Handshake Sonrası veya Plaintext Durumunda Startup Mesajını İşle ---
	log.Printf("Proceeding to parse StartupMessage from %s (TLS: %v)", remoteAddr, conn != initialConn)
	startupMsg, err := p.parseStartupMessage(startupMessageReader) // Artık reader'dan okuyoruz
	if err != nil {
		log.Printf("Error parsing startup message from %s: %v", remoteAddr, err)
		// Hata yanıtı göndermeyi deneyebiliriz, ancak protokolün hangi aşamasında olduğumuza bağlı
		// _ = p.sendErrorResponse(conn, &ErrorResponse{Severity: "FATAL", Code: "08P01", Message: "bad startup packet"})
		return
	}

	// Bağlantı bilgilerini her zaman logla
	p.printStartupInfo(startupMsg)

	// Kullanıcı adını doğrula/değiştir ve hedef servisi bul
	svc, ok, errResp := p.validateAndModifyUsername(startupMsg)
	if !ok {
		log.Printf("Username validation failed for %s: %s", remoteAddr, errResp.Message)
		if sendErr := p.sendErrorResponse(conn, errResp); sendErr != nil {
			log.Printf("Error sending validation error response to %s: %v", remoteAddr, sendErr)
		}
		return // Hata sonrası bağlantıyı kapat
	}

	// Bağlantıyı hedef PostgreSQL sunucusuna ilet (Backend HER ZAMAN plaintext)
	// forwardConnection'a geçen 'conn', TLS ise tls.Conn, değilse net.Conn olur.
	// Ancak forwardConnection içindeki io.Copy bunu transparan olarak halleder.
	if err := p.forwardConnection(conn, startupMsg, svc); err != nil {
		log.Printf("Error forwarding connection from %s to %s:%d: %v", remoteAddr, svc.ClusterIP, svc.Port, err)
		// İletme hatası durumunda istemciye generic bir hata gönderelim
		_ = p.sendErrorResponse(conn, &ErrorResponse{
			Severity: "FATAL",
			Code:     "08001", // sqlclient_unable_to_establish_sqlconnection
			Message:  fmt.Sprintf("failed to connect to backend service %s/%s: %v", svc.Namespace, svc.Name, err),
		})
		return
	}

	log.Printf("Connection handling finished for %s", remoteAddr)
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
	// Bu fonksiyon aynı kalabilir
	log.Printf("=== PostgreSQL Connection Info (Proto: %d) ===", params.ProtocolVersion)
	if user, ok := params.Parameters["user"]; ok {
		log.Printf("  → Raw Username: %s", user) // Henüz değiştirilmemiş olabilir
	}
	if db, ok := params.Parameters["database"]; ok {
		log.Printf("  → Database: %s", db)
	}
	if app, ok := params.Parameters["application_name"]; ok {
		log.Printf("  → Application: %s", app)
	}
	// SSL/TLS durumunu göster
	if ssl, ok := params.Parameters["sslmode"]; ok {
		log.Printf("  → SSL Mode: %s", ssl)
	} else {
		log.Printf("  → SSL Mode: disabled (plain text)")
	}
	var otherParams []string
	for key, value := range params.Parameters {
		if key == "user" || key == "database" || key == "application_name" || key == "sslmode" {
			continue
		}
		otherParams = append(otherParams, fmt.Sprintf("%s=%s", key, value))
	}
	if len(otherParams) > 0 {
		log.Printf("  → Other Params: %s", strings.Join(otherParams, ", "))
	}
	log.Printf("============================================")
}

// forwardConnection establishes a plain TCP connection to the backend and proxies data.
// clientConn can be either net.Conn or tls.Conn. Backend connection is always net.Conn.
func (p *PostgresProxy) forwardConnection(clientConn net.Conn, startupMsg *StartupParameters, service *kubernetes.ServiceInfo) error {
	backendAddr := fmt.Sprintf("%s:%d", service.ClusterDNS, service.Port) // ClusterIP veya ClusterDNS
	log.Printf("Forwarding connection from %s to plaintext backend: %s", clientConn.RemoteAddr(), backendAddr)

	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		return fmt.Errorf("error connecting to backend %s: %v", backendAddr, err)
	}
	defer backendConn.Close()

	log.Printf("Connected to backend %s successfully.", backendAddr)

	// Değiştirilmiş startup mesajını backend'e gönder
	if _, err := backendConn.Write(startupMsg.RawMessage); err != nil {
		// Backend'e yazma hatası olursa bağlantıyı kapat ve hata döndür
		return fmt.Errorf("error forwarding modified startup message to backend %s: %v", backendAddr, err)
	}
	log.Printf("Forwarded modified startup message to backend %s.", backendAddr)

	// Veri akışını çift yönlü kopyala
	var wg sync.WaitGroup
	wg.Add(2)

	clientDesc := fmt.Sprintf("client %s", clientConn.RemoteAddr())
	backendDesc := fmt.Sprintf("backend %s", backendAddr)

	copyData := func(dst net.Conn, src net.Conn, srcDesc, dstDesc string) {
		defer wg.Done()
		// Kaynaktan okuma veya hedefe yazma hatası olursa diğer bağlantıyı da kapatmayı dene
		defer func() {
			if tcpConn, ok := dst.(*net.TCPConn); ok {
				_ = tcpConn.CloseWrite() // Yazma tarafını kapat
			} else if tlsConn, ok := dst.(*tls.Conn); ok {
				_ = tlsConn.CloseWrite() // TLS için de CloseWrite var
			} else {
				// Diğer türler için Close dene (ama bu okumayı da kapatabilir)
				_ = dst.Close()
			}
			log.Printf("Copy routine finished: %s -> %s", srcDesc, dstDesc)
		}()

		copied, err := io.Copy(dst, src)
		log.Printf("Copied %d bytes: %s -> %s", copied, srcDesc, dstDesc)
		if err != nil {
			// "use of closed network connection" hatasını görmezden gel, diğer hataları logla
			// io.EOF normal bir kapanmadır, onu da loglamaya gerek yok.
			netErr, isNetErr := err.(net.Error)
			if err != io.EOF && (!isNetErr || !netErr.Timeout()) && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("Error during copy %s -> %s: %v", srcDesc, dstDesc, err)
			}
		}
	}

	go copyData(backendConn, clientConn, clientDesc, backendDesc)
	go copyData(clientConn, backendConn, backendDesc, clientDesc)

	wg.Wait() // İki kopyalama işlemi de bitene kadar bekle
	log.Printf("Data forwarding finished between %s and %s.", clientDesc, backendDesc)
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
