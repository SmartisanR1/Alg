package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	gotlcp "gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
)

// TLSConnectRequest represents a TLS/TLCP connection request
type TLSConnectRequest struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	Protocol          string `json:"protocol"` // tls1.0, tls1.1, tls1.2, tls1.3, tlcp
	ServerName        string `json:"serverName"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	CACertPEM         string `json:"caCertPEM"`
	ClientCertPEM     string `json:"clientCertPEM"`
	ClientKeyPEM      string `json:"clientKeyPEM"`
	// TLCP dual-cert
	ClientEncCertPEM string `json:"clientEncCertPEM"`
	ClientEncKeyPEM  string `json:"clientEncKeyPEM"`
	TimeoutMs        int    `json:"timeoutMs"`
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
		// Format as colon-separated hex
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

// TLSConnect performs a TLS/TLCP connection and returns connection details
func TLSConnect(req TLSConnectRequest) TLSConnectResult {
	host := strings.TrimSpace(req.Host)
	if host == "" {
		return TLSConnectResult{Error: "主机地址不能为空"}
	}

	port := req.Port
	if port == 0 {
		if req.Protocol == "tlcp" {
			port = 443
		} else {
			port = 443
		}
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

	config := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: req.InsecureSkipVerify,
		RootCAs:            rootCAs,
		Certificates:       certificates,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
	}

	dialer := &net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err != nil {
		return TLSConnectResult{Error: "TLS 连接失败: " + err.Error()}
	}
	defer conn.Close()

	handshakeTime := time.Since(start).Milliseconds()
	state := conn.ConnectionState()

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
