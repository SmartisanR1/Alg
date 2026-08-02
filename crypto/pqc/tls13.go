package pqc

import (
	"encoding/hex"
	"fmt"

	"cryptokit/crypto/symmetric"

	"github.com/emmansun/gmsm/rand"
	"github.com/emmansun/gmsm/tls13"
)

// TLS13KeyExchangeRequest represents a TLS 1.3 key exchange request
type TLS13KeyExchangeRequest struct {
	Group string `json:"group"` // CurveID name: X25519, P256, P384, P521, SM2, X25519MLKEM768, P256MLKEM768, P384MLKEM1024, SM2MLKEM768
}

// TLS13KeyGenResult represents the result of key generation
type TLS13KeyGenResult struct {
	Success    bool   `json:"success"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
	Group      string `json:"group"`
	Error      string `json:"error"`
}

// TLS13ExchangeResult represents the result of key exchange
type TLS13ExchangeResult struct {
	Success       bool   `json:"success"`
	SharedSecret  string `json:"sharedSecret"`
	ServerKeyShare string `json:"serverKeyShare"`
	Error         string `json:"error"`
}

// TLS13ClientResult represents the result of client-side key exchange
type TLS13ClientResult struct {
	Success      bool   `json:"success"`
	SharedSecret string `json:"sharedSecret"`
	Error        string `json:"error"`
}

// getCurveID maps group name to CurveID
func getCurveID(group string) (tls13.CurveID, error) {
	switch group {
	case "X25519":
		return tls13.CurveX25519, nil
	case "P256", "secp256r1":
		return tls13.CurveP256, nil
	case "P384", "secp384r1":
		return tls13.CurveP384, nil
	case "P521", "secp521r1":
		return tls13.CurveP521, nil
	case "SM2":
		return tls13.CurveSM2, nil
	case "X25519MLKEM768":
		return tls13.X25519MLKEM768, nil
	case "P256MLKEM768", "SecP256r1MLKEM768":
		return tls13.SecP256r1MLKEM768, nil
	case "P384MLKEM1024", "SecP384r1MLKEM1024":
		return tls13.SecP384r1MLKEM1024, nil
	case "SM2MLKEM768":
		return tls13.SM2MLKEM768, nil
	default:
		return 0, fmt.Errorf("不支持的密钥交换组: %s", group)
	}
}

// TLS13KeyGen generates a key pair for TLS 1.3 key exchange.
//
// TLS 1.3 使用临时(ephemeral)密钥: gmsm/tls13 库的 ClassicalKeyPair 接口
// 只暴露公钥(PublicKeyBytes)与 ECDH 计算, 不提供私钥字节导出 API
// (stdlib crypto/ecdh.PrivateKey 无 Bytes(), ML-KEM 私钥同样不可导出)。
// 因此这里只返回公钥, 私钥仅存在于内存中, 用于后续 ClientSharedSecret。
func TLS13KeyGen(group string) TLS13KeyGenResult {
	curveID, err := getCurveID(group)
	if err != nil {
		return TLS13KeyGenResult{Error: err.Error()}
	}

	ke, err := tls13.NewKeyExchange(curveID)
	if err != nil {
		return TLS13KeyGenResult{Error: "创建密钥交换实例失败: " + err.Error()}
	}

	_, keyShares, err := ke.KeyShares(rand.Reader)
	if err != nil {
		return TLS13KeyGenResult{Error: "生成密钥对失败: " + err.Error()}
	}

	// The public key is the client key share data
	pubBytes := keyShares[0].Data

	return TLS13KeyGenResult{
		Success:    true,
		PublicKey:  hexUpper(pubBytes),
		PrivateKey: "(临时密钥) TLS 1.3 密钥交换使用瞬时密钥, 私钥由 gmsm 库在内存中持有, 不支持导出。请使用\"执行完整密钥交换\"完成演示。",
		Group:      group,
	}
}

// TLS13ServerExchange performs server-side key exchange
func TLS13ServerExchange(req TLS13KeyExchangeRequest) TLS13ExchangeResult {
	curveID, err := getCurveID(req.Group)
	if err != nil {
		return TLS13ExchangeResult{Error: err.Error()}
	}

	ke, err := tls13.NewKeyExchange(curveID)
	if err != nil {
		return TLS13ExchangeResult{Error: "创建密钥交换实例失败: " + err.Error()}
	}

	// Server generates its own ephemeral key and computes shared secret
	// using the client's key share (empty in this case, so we generate both sides)
	_, clientKeyShares, err := ke.KeyShares(rand.Reader)
	if err != nil {
		return TLS13ExchangeResult{Error: "生成客户端密钥失败: " + err.Error()}
	}

	sharedSecret, serverKeyShare, err := ke.ServerSharedSecret(rand.Reader, clientKeyShares[0].Data)
	if err != nil {
		return TLS13ExchangeResult{Error: "服务器密钥交换失败: " + err.Error()}
	}

	return TLS13ExchangeResult{
		Success:        true,
		SharedSecret:   hexUpper(sharedSecret),
		ServerKeyShare: hexUpper(serverKeyShare.Data),
	}
}

// TLS13ClientExchange performs client-side key exchange
func TLS13ClientExchange(group string, serverKeyShareHex string) TLS13ClientResult {
	curveID, err := getCurveID(group)
	if err != nil {
		return TLS13ClientResult{Error: err.Error()}
	}

	serverKeyShare, err := hex.DecodeString(serverKeyShareHex)
	if err != nil {
		return TLS13ClientResult{Error: "无效的服务器密钥分享: " + err.Error()}
	}

	ke, err := tls13.NewKeyExchange(curveID)
	if err != nil {
		return TLS13ClientResult{Error: "创建密钥交换实例失败: " + err.Error()}
	}

	priv, _, err := ke.KeyShares(rand.Reader)
	if err != nil {
		return TLS13ClientResult{Error: "生成客户端密钥失败: " + err.Error()}
	}

	sharedSecret, err := ke.ClientSharedSecret(priv, serverKeyShare)
	if err != nil {
		return TLS13ClientResult{Error: "客户端密钥交换失败: " + err.Error()}
	}

	return TLS13ClientResult{
		Success:      true,
		SharedSecret: hexUpper(sharedSecret),
	}
}

// TLS13FullExchange performs a full key exchange (both client and server) for demonstration
func TLS13FullExchange(group string) symmetric.CryptoResult {
	curveID, err := getCurveID(group)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}

	ke, err := tls13.NewKeyExchange(curveID)
	if err != nil {
		return symmetric.CryptoResult{Error: "创建密钥交换实例失败: " + err.Error()}
	}

	// Client side
	clientPriv, clientKeyShares, err := ke.KeyShares(rand.Reader)
	if err != nil {
		return symmetric.CryptoResult{Error: "客户端密钥生成失败: " + err.Error()}
	}

	// Server side
	sharedSecret1, serverKeyShare, err := ke.ServerSharedSecret(rand.Reader, clientKeyShares[0].Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "服务器密钥交换失败: " + err.Error()}
	}

	// Client computes shared secret
	sharedSecret2, err := ke.ClientSharedSecret(clientPriv, serverKeyShare.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "客户端密钥交换失败: " + err.Error()}
	}

	// Verify both sides got the same shared secret
	if hex.EncodeToString(sharedSecret1) != hex.EncodeToString(sharedSecret2) {
		return symmetric.CryptoResult{Error: "密钥交换验证失败: 双方共享密钥不一致"}
	}

	return symmetric.CryptoResult{
		Success: true,
		Data:    hexUpper(sharedSecret1),
		Extra:   fmt.Sprintf("客户端公钥: %s\n服务器公钥: %s", hexUpper(clientKeyShares[0].Data), hexUpper(serverKeyShare.Data)),
	}
}
