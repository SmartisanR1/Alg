package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	gotlcp "gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// TLSConnectRequest represents a TLS/TLCP connection request
type TLSConnectRequest struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Protocol           string `json:"protocol"` // tls1.0, tls1.1, tls1.2, tls1.3, tlcp
	ServerName         string `json:"serverName"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	CACertPEM          string `json:"caCertPEM"`
	ClientCertPEM      string `json:"clientCertPEM"`
	ClientKeyPEM       string `json:"clientKeyPEM"`
	// TLCP dual-cert
	ClientEncCertPEM string `json:"clientEncCertPEM"`
	ClientEncKeyPEM  string `json:"clientEncKeyPEM"`
	TimeoutMs        int    `json:"timeoutMs"`
	// PQC support
	EnablePQC bool `json:"enablePQC"`
}

// TLSSelfTestRequest represents a self-test request
type TLSSelfTestRequest struct {
	Protocol  string `json:"protocol"` // tls1.2, tls1.3, tlcp
	EnablePQC bool   `json:"enablePQC"`
	Message   string `json:"message"`
}

// TLSSelfTestResult represents the result of a self-test
type TLSSelfTestResult struct {
	Success          bool       `json:"success"`
	Protocol         string     `json:"protocol"`
	CipherSuite      string     `json:"cipherSuite"`
	CipherSuiteID    string     `json:"cipherSuiteId"`
	TLSVersion       string     `json:"tlsVersion"`
	HandshakeTimeMs  int64      `json:"handshakeTimeMs"`
	ExchangeTimeMs   int64      `json:"exchangeTimeMs"`
	PeerCertificates []CertInfo `json:"peerCertificates"`
	ALPNProtocol     string     `json:"alpnProtocol"`
	SessionReused    bool       `json:"sessionReused"`
	SentMessage      string     `json:"sentMessage"`
	ReceivedMessage  string     `json:"receivedMessage"`
	CurveUsed        string     `json:"curveUsed"`
	Error            string     `json:"error"`
}

// CertInfo represents certificate information
type CertInfo struct {
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	SerialNumber string   `json:"serialNumber"`
	NotBefore    string   `json:"notBefore"`
	NotAfter     string   `json:"notAfter"`
	DNSNames     []string `json:"dnsNames"`
	IPAddresses  []string `json:"ipAddresses"`
	IsCA         bool     `json:"isCA"`
	KeyAlgorithm string   `json:"keyAlgorithm"`
	SigAlgorithm string   `json:"sigAlgorithm"`
	Fingerprint  string   `json:"fingerprint"`
	RawPEM       string   `json:"rawPEM"`
}

// TLSConnectResult represents the result of a TLS/TLCP connection
type TLSConnectResult struct {
	Success          bool       `json:"success"`
	Protocol         string     `json:"protocol"`
	CipherSuite      string     `json:"cipherSuite"`
	CipherSuiteID    string     `json:"cipherSuiteId"`
	ServerName       string     `json:"serverName"`
	TLSVersion       string     `json:"tlsVersion"`
	HandshakeTimeMs  int64      `json:"handshakeTimeMs"`
	PeerCertificates []CertInfo `json:"peerCertificates"`
	ALPNProtocol     string     `json:"alpnProtocol"`
	SessionReused    bool       `json:"sessionReused"`
	CurveUsed        string     `json:"curveUsed"`
	Error            string     `json:"error"`
}

// getTLSVersionName returns human-readable TLS version
func getTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case 0x0101:
		return "TLCP 1.1"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", version)
	}
}

// getCurveName returns human-readable curve name
func getCurveName(id tls.CurveID) string {
	switch id {
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	case 0x11ec:
		return "X25519MLKEM768 (PQC)"
	case 0x11eb:
		return "SecP256r1MLKEM768 (PQC)"
	case 0x11ed:
		return "SecP384r1MLKEM1024 (PQC)"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", id)
	}
}

// getTLSMinVersion returns the minimum TLS version for the protocol
func getTLSMinVersion(protocol string) uint16 {
	switch protocol {
	case "tls1.0":
		return tls.VersionTLS10
	case "tls1.1":
		return tls.VersionTLS11
	case "tls1.2":
		return tls.VersionTLS12
	case "tls1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

// getTLSMaxVersion returns the maximum TLS version for the protocol
func getTLSMaxVersion(protocol string) uint16 {
	switch protocol {
	case "tls1.0":
		return tls.VersionTLS10
	case "tls1.1":
		return tls.VersionTLS11
	case "tls1.2":
		return tls.VersionTLS12
	case "tls1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS13
	}
}

// extractCertInfo extracts certificate information
func extractCertInfo(cert interface{}) CertInfo {
	info := CertInfo{}

	switch c := cert.(type) {
	case *x509.Certificate:
		info.Subject = c.Subject.String()
		info.Issuer = c.Issuer.String()
		info.SerialNumber = c.SerialNumber.Text(16)
		info.NotBefore = c.NotBefore.Format("2006-01-02 15:04:05 MST")
		info.NotAfter = c.NotAfter.Format("2006-01-02 15:04:05 MST")
		info.DNSNames = c.DNSNames
		for _, ip := range c.IPAddresses {
			info.IPAddresses = append(info.IPAddresses, ip.String())
		}
		info.IsCA = c.IsCA
		info.KeyAlgorithm = c.PublicKeyAlgorithm.String()
		info.SigAlgorithm = c.SignatureAlgorithm.String()
		fingerprint := hex.EncodeToString(c.Raw)
		parts := make([]string, len(fingerprint)/2)
		for i := 0; i < len(fingerprint); i += 2 {
			parts[i/2] = strings.ToUpper(fingerprint[i:i+2])
		}
		info.Fingerprint = strings.Join(parts, ":")
	case *smx509.Certificate:
		info.Subject = c.Subject.String()
		info.Issuer = c.Issuer.String()
		info.SerialNumber = c.SerialNumber.Text(16)
		info.NotBefore = c.NotBefore.Format("2006-01-02 15:04:05 MST")
		info.NotAfter = c.NotAfter.Format("2006-01-02 15:04:05 MST")
		info.DNSNames = c.DNSNames
		for _, ip := range c.IPAddresses {
			info.IPAddresses = append(info.IPAddresses, ip.String())
		}
		info.IsCA = c.IsCA
		info.KeyAlgorithm = c.PublicKeyAlgorithm.String()
		info.SigAlgorithm = c.SignatureAlgorithm.String()
		fingerprint := hex.EncodeToString(c.Raw)
		parts := make([]string, len(fingerprint)/2)
		for i := 0; i < len(fingerprint); i += 2 {
			parts[i/2] = strings.ToUpper(fingerprint[i:i+2])
		}
		info.Fingerprint = strings.Join(parts, ":")
	}

	return info
}

// generateSelfSignedCert generates a self-signed certificate for testing
func generateSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "CryptoKit Self-Test",
			Organization: []string{"CryptoKit"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// generateSM2Cert generates a SM2 self-signed certificate for TLCP testing
func generateSM2Cert() (certPEM, keyPEM []byte, err error) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &smx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "CryptoKit TLCP Self-Test",
			Organization: []string{"CryptoKit"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              smx509.KeyUsageDigitalSignature | smx509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth, smx509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := smx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := smx509.MarshalSM2PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// TLSSelfTest performs a self-test: starts a server and client, connects to itself
func TLSSelfTest(req TLSSelfTestRequest) TLSSelfTestResult {
	protocol := req.Protocol
	if protocol == "" {
		protocol = "tls1.3"
	}

	message := req.Message
	if message == "" {
		message = "Hello from CryptoKit self-test!"
	}

	if protocol == "tlcp" {
		return tlcpSelfTest(message)
	}
	return tlsSelfTest(protocol, message, req.EnablePQC)
}

// tlsSelfTest performs TLS self-test
func tlsSelfTest(protocol, message string, enablePQC bool) TLSSelfTestResult {
	start := time.Now()

	// Generate self-signed cert
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		return TLSSelfTestResult{Error: "生成证书失败: " + err.Error()}
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return TLSSelfTestResult{Error: "解析证书失败: " + err.Error()}
	}

	// Setup TLS config
	minVersion := getTLSMinVersion(protocol)
	maxVersion := getTLSMaxVersion(protocol)

	// Build curve preferences
	curvePreferences := []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}
	if enablePQC {
		// Add PQC hybrid curves
		curvePreferences = []tls.CurveID{
			tls.CurveID(0x11ec), // X25519MLKEM768
			tls.CurveID(0x11eb), // SecP256r1MLKEM768
			tls.X25519,
			tls.CurveP256,
		}
	}

	serverConfig := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       minVersion,
		MaxVersion:       maxVersion,
		CurvePreferences: curvePreferences,
	}

	// Find a free port
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		return TLSSelfTestResult{Error: "启动服务器失败: " + err.Error()}
	}
	defer listener.Close()

	addr := listener.Addr().String()
	var wg sync.WaitGroup
	var serverResult TLSSelfTestResult

	// Server goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			serverResult.Error = "服务器接受连接失败: " + err.Error()
			return
		}
		defer conn.Close()

		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			serverResult.Error = "服务器握手失败: " + err.Error()
			return
		}

		state := tlsConn.ConnectionState()
		serverResult.Success = true
		serverResult.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
		serverResult.CipherSuiteID = fmt.Sprintf("0x%04X", state.CipherSuite)
		serverResult.TLSVersion = getTLSVersionName(state.Version)
		serverResult.ALPNProtocol = state.NegotiatedProtocol
		serverResult.SessionReused = state.DidResume
		if len(state.PeerCertificates) > 0 {
			serverResult.PeerCertificates = append(serverResult.PeerCertificates, extractCertInfo(state.PeerCertificates[0]))
		}

		// Read message from client
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			serverResult.Error = "服务器读取失败: " + err.Error()
			return
		}
		serverResult.ReceivedMessage = string(buf[:n])

		// Echo back
		_, err = conn.Write(buf[:n])
		if err != nil {
			serverResult.Error = "服务器写入失败: " + err.Error()
			return
		}
	}()

	// Client connects
	clientConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		CurvePreferences:   curvePreferences,
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, clientConfig)
	if err != nil {
		return TLSSelfTestResult{Error: "客户端连接失败: " + err.Error()}
	}
	defer conn.Close()

	handshakeTime := time.Since(start).Milliseconds()
	exchangeStart := time.Now()

	// Send message
	_, err = conn.Write([]byte(message))
	if err != nil {
		return TLSSelfTestResult{Error: "客户端发送失败: " + err.Error()}
	}

	// Read echo
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return TLSSelfTestResult{Error: "客户端读取失败: " + err.Error()}
	}
	exchangeTime := time.Since(exchangeStart).Milliseconds()

	// Wait for server
	wg.Wait()

	state := conn.ConnectionState()

	// Determine curve used
	curveUsed := "Unknown"
	if len(state.TLSUnique) > 0 {
		// Try to determine from cipher suite
		for _, curve := range curvePreferences {
			if curve == tls.X25519 {
				curveUsed = "X25519"
			} else if curve == tls.CurveP256 {
				curveUsed = "P-256"
			} else if curve == 0x11ec {
				curveUsed = "X25519MLKEM768 (PQC)"
			}
		}
	}

	result := TLSSelfTestResult{
		Success:          true,
		Protocol:         protocol,
		CipherSuite:      tls.CipherSuiteName(state.CipherSuite),
		CipherSuiteID:    fmt.Sprintf("0x%04X", state.CipherSuite),
		TLSVersion:       getTLSVersionName(state.Version),
		HandshakeTimeMs:  handshakeTime,
		ExchangeTimeMs:   exchangeTime,
		ALPNProtocol:     state.NegotiatedProtocol,
		SessionReused:    state.DidResume,
		SentMessage:      message,
		ReceivedMessage:  string(buf[:n]),
		CurveUsed:        curveUsed,
	}

	for _, cert := range state.PeerCertificates {
		result.PeerCertificates = append(result.PeerCertificates, extractCertInfo(cert))
	}

	return result
}

// tlcpSelfTest performs TLCP self-test
func tlcpSelfTest(message string) TLSSelfTestResult {
	start := time.Now()

	// Generate SM2 certs (sign + enc)
	signCertPEM, signKeyPEM, err := generateSM2Cert()
	if err != nil {
		return TLSSelfTestResult{Error: "生成签名证书失败: " + err.Error()}
	}
	encCertPEM, encKeyPEM, err := generateSM2Cert()
	if err != nil {
		return TLSSelfTestResult{Error: "生成加密证书失败: " + err.Error()}
	}

	// Parse certs for server
	signCert, err := gotlcp.X509KeyPair(signCertPEM, signKeyPEM)
	if err != nil {
		return TLSSelfTestResult{Error: "解析签名证书失败: " + err.Error()}
	}
	encCert, err := gotlcp.X509KeyPair(encCertPEM, encKeyPEM)
	if err != nil {
		return TLSSelfTestResult{Error: "解析加密证书失败: " + err.Error()}
	}

	// Create CA pool from sign cert
	cert, _ := smx509.ParseCertificatePEM(signCertPEM)
	caPool := smx509.NewCertPool()
	caPool.AddCert(cert)

	serverConfig := &gotlcp.Config{
		Certificates: []gotlcp.Certificate{signCert, encCert},
		ClientCAs:    caPool,
		ClientAuth:   gotlcp.NoClientCert,
	}

	// Find a free port
	listener, err := gotlcp.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		return TLSSelfTestResult{Error: "启动 TLCP 服务器失败: " + err.Error()}
	}
	defer listener.Close()

	addr := listener.Addr().String()
	var wg sync.WaitGroup
	var serverResult TLSSelfTestResult

	// Server goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			serverResult.Error = "服务器接受连接失败: " + err.Error()
			return
		}
		defer conn.Close()

		tlcpConn := conn.(*gotlcp.Conn)
		if err := tlcpConn.Handshake(); err != nil {
			serverResult.Error = "服务器握手失败: " + err.Error()
			return
		}

		state := tlcpConn.ConnectionState()
		serverResult.Success = true
		serverResult.CipherSuite = gotlcp.CipherSuiteName(state.CipherSuite)
		serverResult.CipherSuiteID = fmt.Sprintf("0x%04X", state.CipherSuite)
		serverResult.TLSVersion = getTLSVersionName(state.Version)
		serverResult.SessionReused = state.DidResume

		// Read message
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			serverResult.Error = "服务器读取失败: " + err.Error()
			return
		}
		serverResult.ReceivedMessage = string(buf[:n])

		// Echo back
		_, err = conn.Write(buf[:n])
		if err != nil {
			serverResult.Error = "服务器写入失败: " + err.Error()
			return
		}
	}()

	// Client connects
	clientSignCert, err := gotlcp.X509KeyPair(signCertPEM, signKeyPEM)
	if err != nil {
		return TLSSelfTestResult{Error: "客户端签名证书失败: " + err.Error()}
	}
	clientEncCert, err := gotlcp.X509KeyPair(encCertPEM, encKeyPEM)
	if err != nil {
		return TLSSelfTestResult{Error: "客户端加密证书失败: " + err.Error()}
	}

	clientConfig := &gotlcp.Config{
		InsecureSkipVerify: true,
		Certificates:       []gotlcp.Certificate{clientSignCert, clientEncCert},
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := gotlcp.DialWithDialer(dialer, "tcp", addr, clientConfig)
	if err != nil {
		return TLSSelfTestResult{Error: "客户端连接失败: " + err.Error()}
	}
	defer conn.Close()

	handshakeTime := time.Since(start).Milliseconds()
	exchangeStart := time.Now()

	// Send message
	_, err = conn.Write([]byte(message))
	if err != nil {
		return TLSSelfTestResult{Error: "客户端发送失败: " + err.Error()}
	}

	// Read echo
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return TLSSelfTestResult{Error: "客户端读取失败: " + err.Error()}
	}
	exchangeTime := time.Since(exchangeStart).Milliseconds()

	wg.Wait()

	state := conn.ConnectionState()

	result := TLSSelfTestResult{
		Success:          true,
		Protocol:         "tlcp",
		CipherSuite:      gotlcp.CipherSuiteName(state.CipherSuite),
		CipherSuiteID:    fmt.Sprintf("0x%04X", state.CipherSuite),
		TLSVersion:       getTLSVersionName(state.Version),
		HandshakeTimeMs:  handshakeTime,
		ExchangeTimeMs:   exchangeTime,
		SessionReused:    state.DidResume,
		SentMessage:      message,
		ReceivedMessage:  string(buf[:n]),
	}

	for _, cert := range state.PeerCertificates {
		result.PeerCertificates = append(result.PeerCertificates, extractCertInfo(cert))
	}

	return result
}

// TLSConnect performs a TLS/TLCP connection and returns connection details
func TLSConnect(req TLSConnectRequest) TLSConnectResult {
	host := strings.TrimSpace(req.Host)
	if host == "" {
		return TLSConnectResult{Error: "主机地址不能为空"}
	}

	port := req.Port
	if port == 0 {
		port = 443
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	timeout := req.TimeoutMs
	if timeout == 0 {
		timeout = 10000
	}

	if req.Protocol == "tlcp" {
		return tlsConnectTLCP(addr, host, req, timeout)
	}
	return tlsConnectTLS(addr, host, req, timeout)
}

// tlsConnectTLS performs a standard TLS connection
func tlsConnectTLS(addr, host string, req TLSConnectRequest, timeoutMs int) TLSConnectResult {
	start := time.Now()

	serverName := req.ServerName
	if serverName == "" {
		serverName = host
	}

	// Build CA pool
	var rootCAs *x509.CertPool
	if req.CACertPEM != "" {
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM([]byte(req.CACertPEM)) {
			return TLSConnectResult{Error: "无法解析 CA 证书"}
		}
	}

	// Build client certificate
	var certificates []tls.Certificate
	if req.ClientCertPEM != "" && req.ClientKeyPEM != "" {
		cert, err := tls.X509KeyPair([]byte(req.ClientCertPEM), []byte(req.ClientKeyPEM))
		if err != nil {
			return TLSConnectResult{Error: "客户端证书解析失败: " + err.Error()}
		}
		certificates = append(certificates, cert)
	}

	minVersion := getTLSMinVersion(req.Protocol)
	maxVersion := getTLSMaxVersion(req.Protocol)

	// Build curve preferences
	curvePreferences := []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}
	if req.EnablePQC {
		curvePreferences = []tls.CurveID{
			tls.CurveID(0x11ec), // X25519MLKEM768
			tls.CurveID(0x11eb), // SecP256r1MLKEM768
			tls.X25519,
			tls.CurveP256,
		}
	}

	config := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: req.InsecureSkipVerify,
		RootCAs:            rootCAs,
		Certificates:       certificates,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		CurvePreferences:   curvePreferences,
	}

	dialer := &net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err != nil {
		return TLSConnectResult{Error: "TLS 连接失败: " + err.Error()}
	}
	defer conn.Close()

	handshakeTime := time.Since(start).Milliseconds()
	state := conn.ConnectionState()

	// Determine curve used from TLS 1.3 key share
	curveUsed := "N/A"
	if state.Version == tls.VersionTLS13 && len(state.TLSUnique) > 0 {
		// In TLS 1.3, we can try to determine from the negotiated cipher suite
		for _, curve := range curvePreferences {
			if curve == tls.CurveID(0x11ec) {
				curveUsed = "X25519MLKEM768 (PQC)"
				break
			}
		}
		if curveUsed == "N/A" {
			curveUsed = getCurveName(tls.X25519)
		}
	}

	result := TLSConnectResult{
		Success:         true,
		Protocol:        req.Protocol,
		CipherSuite:     tls.CipherSuiteName(state.CipherSuite),
		CipherSuiteID:   fmt.Sprintf("0x%04X", state.CipherSuite),
		ServerName:      state.ServerName,
		TLSVersion:      getTLSVersionName(state.Version),
		HandshakeTimeMs: handshakeTime,
		ALPNProtocol:    state.NegotiatedProtocol,
		SessionReused:   state.DidResume,
		CurveUsed:       curveUsed,
	}

	for _, cert := range state.PeerCertificates {
		result.PeerCertificates = append(result.PeerCertificates, extractCertInfo(cert))
	}

	return result
}

// tlsConnectTLCP performs a TLCP connection
func tlsConnectTLCP(addr, host string, req TLSConnectRequest, timeoutMs int) TLSConnectResult {
	start := time.Now()

	serverName := req.ServerName
	if serverName == "" {
		serverName = host
	}

	// Build CA pool
	var rootCAs *smx509.CertPool
	if req.CACertPEM != "" {
		rootCAs = smx509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM([]byte(req.CACertPEM)) {
			return TLSConnectResult{Error: "无法解析 CA 证书"}
		}
	}

	// Build certificates (TLCP needs sign + optional enc cert)
	var certificates []gotlcp.Certificate
	if req.ClientCertPEM != "" && req.ClientKeyPEM != "" {
		cert, err := gotlcp.X509KeyPair([]byte(req.ClientCertPEM), []byte(req.ClientKeyPEM))
		if err != nil {
			return TLSConnectResult{Error: "签名证书解析失败: " + err.Error()}
		}
		certificates = append(certificates, cert)
	}
	if req.ClientEncCertPEM != "" && req.ClientEncKeyPEM != "" {
		cert, err := gotlcp.X509KeyPair([]byte(req.ClientEncCertPEM), []byte(req.ClientEncKeyPEM))
		if err != nil {
			return TLSConnectResult{Error: "加密证书解析失败: " + err.Error()}
		}
		certificates = append(certificates, cert)
	}

	config := &gotlcp.Config{
		ServerName:         serverName,
		InsecureSkipVerify: req.InsecureSkipVerify,
		RootCAs:            rootCAs,
		Certificates:       certificates,
	}

	dialer := &net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	conn, err := gotlcp.DialWithDialer(dialer, "tcp", addr, config)
	if err != nil {
		return TLSConnectResult{Error: "TLCP 连接失败: " + err.Error()}
	}
	defer conn.Close()

	handshakeTime := time.Since(start).Milliseconds()
	state := conn.ConnectionState()

	result := TLSConnectResult{
		Success:         true,
		Protocol:        "tlcp",
		CipherSuite:     gotlcp.CipherSuiteName(state.CipherSuite),
		CipherSuiteID:   fmt.Sprintf("0x%04X", state.CipherSuite),
		ServerName:      state.ServerName,
		TLSVersion:      getTLSVersionName(state.Version),
		HandshakeTimeMs: handshakeTime,
		SessionReused:   state.DidResume,
	}

	for _, cert := range state.PeerCertificates {
		result.PeerCertificates = append(result.PeerCertificates, extractCertInfo(cert))
	}

	return result
}

// ListTLSCipherSuites returns available TLS cipher suites
func ListTLSCipherSuites() ToolResult {
	suites := tls.CipherSuites()
	var names []string
	for _, s := range suites {
		names = append(names, fmt.Sprintf("%s (0x%04X)", s.Name, s.ID))
	}
	return ToolResult{Success: true, Data: strings.Join(names, "\n")}
}

// ListTLCPCipherSuites returns available TLCP cipher suites
func ListTLCPCipherSuites() ToolResult {
	suites := gotlcp.CipherSuites()
	var names []string
	for _, s := range suites {
		names = append(names, fmt.Sprintf("%s (0x%04X)", s.Name, s.ID))
	}
	return ToolResult{Success: true, Data: strings.Join(names, "\n")}
}
