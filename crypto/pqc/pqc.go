package pqc

import (
	"crypto/rand"
	"encoding/hex"

	"cryptokit/crypto/symmetric"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/cloudflare/circl/sign/slhdsa"
)

type PQCKeyResult struct {
	Success    bool   `json:"success"`
	PrivateKey string `json:"privateKey"` // hex
	PublicKey  string `json:"publicKey"`  // hex
	ParamSet   string `json:"paramSet"`
	Error      string `json:"error"`
}

type PQCEncapResult struct {
	Success      bool   `json:"success"`
	Ciphertext   string `json:"ciphertext"`   // hex
	SharedSecret string `json:"sharedSecret"` // hex
	Error        string `json:"error"`
}

// ============================================================
// ML-KEM (CRYSTALS-Kyber) — FIPS 203
// ============================================================

type MLKEMRequest struct {
	PublicKey string `json:"publicKey"` // hex
	ParamSet  string `json:"paramSet"`  // ML-KEM-512 ML-KEM-768 ML-KEM-1024
}

type MLKEMDecapRequest struct {
	PrivateKey string `json:"privateKey"` // hex
	Ciphertext string `json:"ciphertext"` // hex
	ParamSet   string `json:"paramSet"`
}

func MLKEMKeyGen(paramSet string) PQCKeyResult {
	switch paramSet {
	case "ML-KEM-512":
		// 当前引入的 circl 版本的 kyber512 API 与旧代码不兼容，这里先返回明确错误，避免编译失败。
		return PQCKeyResult{Error: "当前 circl 版本暂不支持 ML-KEM-512，请使用 ML-KEM-768 或 ML-KEM-1024"}

	case "ML-KEM-768":
		pub, priv, err := kyber768.GenerateKeyPair(rand.Reader)
		if err != nil {
			return PQCKeyResult{Error: "ML-KEM-768 密钥生成失败: " + err.Error()}
		}
		pubBytes, _ := pub.MarshalBinary()
		privBytes, _ := priv.MarshalBinary()
		return PQCKeyResult{
			Success:    true,
			PublicKey:  hexUpper(pubBytes),
			PrivateKey: hexUpper(privBytes),
			ParamSet:   "ML-KEM-768",
		}

	default: // ML-KEM-1024
		pub, priv, err := kyber1024.GenerateKeyPair(rand.Reader)
		if err != nil {
			return PQCKeyResult{Error: "ML-KEM-1024 密钥生成失败: " + err.Error()}
		}
		pubBytes, _ := pub.MarshalBinary()
		privBytes, _ := priv.MarshalBinary()
		return PQCKeyResult{
			Success:    true,
			PublicKey:  hexUpper(pubBytes),
			PrivateKey: hexUpper(privBytes),
			ParamSet:   "ML-KEM-1024",
		}
	}
}

func MLKEMEncapsulate(req MLKEMRequest) PQCEncapResult {
	pubBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return PQCEncapResult{Error: "无效的公钥: " + err.Error()}
	}

	// circl v1.6.3 中 Kyber/ML-KEM 的推荐用法是通过 Scheme 接口来完成
	// 反序列化、公钥封装等操作，而不是直接做类型转换或调用包级函数。

	switch req.ParamSet {
	case "ML-KEM-512":
		return PQCEncapResult{Error: "当前 circl 版本暂不支持 ML-KEM-512 封装，请使用 ML-KEM-768 或 ML-KEM-1024"}

	case "ML-KEM-768":
		scheme := kyber768.Scheme()
		pub, err := scheme.UnmarshalBinaryPublicKey(pubBytes)
		if err != nil {
			return PQCEncapResult{Error: "解析ML-KEM-768公钥失败: " + err.Error()}
		}
		ct, ss, err := scheme.Encapsulate(pub)
		if err != nil {
			return PQCEncapResult{Error: "封装失败: " + err.Error()}
		}
		return PQCEncapResult{
			Success:      true,
			Ciphertext:   hexUpper(ct),
			SharedSecret: hexUpper(ss),
		}

	default: // ML-KEM-1024
		scheme := kyber1024.Scheme()
		pub, err := scheme.UnmarshalBinaryPublicKey(pubBytes)
		if err != nil {
			return PQCEncapResult{Error: "解析ML-KEM-1024公钥失败: " + err.Error()}
		}
		ct, ss, err := scheme.Encapsulate(pub)
		if err != nil {
			return PQCEncapResult{Error: "封装失败: " + err.Error()}
		}
		return PQCEncapResult{
			Success:      true,
			Ciphertext:   hexUpper(ct),
			SharedSecret: hexUpper(ss),
		}
	}
}

func MLKEMDecapsulate(req MLKEMDecapRequest) symmetric.CryptoResult {
	privBytes, err := hex.DecodeString(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的私钥: " + err.Error()}
	}
	ctBytes, err := hex.DecodeString(req.Ciphertext)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密文: " + err.Error()}
	}

	switch req.ParamSet {
	case "ML-KEM-512":
		return symmetric.CryptoResult{Error: "当前 circl 版本暂不支持 ML-KEM-512 解封装，请使用 ML-KEM-768 或 ML-KEM-1024"}

	case "ML-KEM-768":
		scheme := kyber768.Scheme()
		priv, err := scheme.UnmarshalBinaryPrivateKey(privBytes)
		if err != nil {
			return symmetric.CryptoResult{Error: "解析ML-KEM-768私钥失败: " + err.Error()}
		}
		ss, err := scheme.Decapsulate(priv, ctBytes)
		if err != nil {
			return symmetric.CryptoResult{Error: "解封装失败: " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(ss)}

	default: // ML-KEM-1024
		scheme := kyber1024.Scheme()
		priv, err := scheme.UnmarshalBinaryPrivateKey(privBytes)
		if err != nil {
			return symmetric.CryptoResult{Error: "解析ML-KEM-1024私钥失败: " + err.Error()}
		}
		ss, err := scheme.Decapsulate(priv, ctBytes)
		if err != nil {
			return symmetric.CryptoResult{Error: "解封装失败: " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(ss)}
	}
}

// ============================================================
// ML-DSA (CRYSTALS-Dilithium) — FIPS 204
// ============================================================

type MLDSARequest struct {
	PrivateKey string `json:"privateKey"` // hex
	Data       string `json:"data"`       // hex
	ParamSet   string `json:"paramSet"`   // ML-DSA-44 ML-DSA-65 ML-DSA-87
}

type MLDSAVerifyRequest struct {
	PublicKey string `json:"publicKey"`
	Data      string `json:"data"`
	Signature string `json:"signature"`
	ParamSet  string `json:"paramSet"`
}

func MLDSAKeyGen(paramSet string) PQCKeyResult {
	switch paramSet {
	case "ML-DSA-44":
		pub, priv, err := mode2.GenerateKey(rand.Reader)
		if err != nil {
			return PQCKeyResult{Error: "ML-DSA-44 密钥生成失败: " + err.Error()}
		}
		pubBytes, _ := pub.MarshalBinary()
		privBytes, _ := priv.MarshalBinary()
		return PQCKeyResult{
			Success:    true,
			PublicKey:  hexUpper(pubBytes),
			PrivateKey: hexUpper(privBytes),
			ParamSet:   "ML-DSA-44",
		}

	case "ML-DSA-65":
		pub, priv, err := mode3.GenerateKey(rand.Reader)
		if err != nil {
			return PQCKeyResult{Error: "ML-DSA-65 密钥生成失败: " + err.Error()}
		}
		pubBytes, _ := pub.MarshalBinary()
		privBytes, _ := priv.MarshalBinary()
		return PQCKeyResult{
			Success:    true,
			PublicKey:  hexUpper(pubBytes),
			PrivateKey: hexUpper(privBytes),
			ParamSet:   "ML-DSA-65",
		}

	default: // ML-DSA-87
		pub, priv, err := mode5.GenerateKey(rand.Reader)
		if err != nil {
			return PQCKeyResult{Error: "ML-DSA-87 密钥生成失败: " + err.Error()}
		}
		pubBytes, _ := pub.MarshalBinary()
		privBytes, _ := priv.MarshalBinary()
		return PQCKeyResult{
			Success:    true,
			PublicKey:  hexUpper(pubBytes),
			PrivateKey: hexUpper(privBytes),
			ParamSet:   "ML-DSA-87",
		}
	}
}

func MLDSASign(req MLDSARequest) symmetric.CryptoResult {
	privBytes, err := hex.DecodeString(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的私钥: " + err.Error()}
	}
	msgBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	switch req.ParamSet {
	case "ML-DSA-44":
		var priv mode2.PrivateKey
		if err := priv.UnmarshalBinary(privBytes); err != nil {
			return symmetric.CryptoResult{Error: "解析ML-DSA-44私钥失败: " + err.Error()}
		}
		scheme := mode2.Scheme()
		sig := scheme.Sign(&priv, msgBytes, nil)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}

	case "ML-DSA-65":
		var priv mode3.PrivateKey
		if err := priv.UnmarshalBinary(privBytes); err != nil {
			return symmetric.CryptoResult{Error: "解析ML-DSA-65私钥失败: " + err.Error()}
		}
		scheme := mode3.Scheme()
		sig := scheme.Sign(&priv, msgBytes, nil)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}

	default: // ML-DSA-87
		var priv mode5.PrivateKey
		if err := priv.UnmarshalBinary(privBytes); err != nil {
			return symmetric.CryptoResult{Error: "解析ML-DSA-87私钥失败: " + err.Error()}
		}
		scheme := mode5.Scheme()
		sig := scheme.Sign(&priv, msgBytes, nil)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}
	}
}

func MLDSAVerify(req MLDSAVerifyRequest) symmetric.CryptoResult {
	pubBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的公钥: " + err.Error()}
	}
	msgBytes, _ := hex.DecodeString(req.Data)
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的签名: " + err.Error()}
	}

	switch req.ParamSet {
	case "ML-DSA-44":
		var pub mode2.PublicKey
		if err := pub.UnmarshalBinary(pubBytes); err != nil {
			return symmetric.CryptoResult{Error: "解析公钥失败: " + err.Error()}
		}
		scheme := mode2.Scheme()
		valid := scheme.Verify(&pub, msgBytes, sigBytes, nil)
		if !valid {
			return symmetric.CryptoResult{Success: true, Data: "false", Error: "签名验证失败"}
		}

	case "ML-DSA-65":
		var pub mode3.PublicKey
		if err := pub.UnmarshalBinary(pubBytes); err != nil {
			return symmetric.CryptoResult{Error: "解析公钥失败: " + err.Error()}
		}
		scheme := mode3.Scheme()
		valid := scheme.Verify(&pub, msgBytes, sigBytes, nil)
		if !valid {
			return symmetric.CryptoResult{Success: true, Data: "false", Error: "签名验证失败"}
		}

	default: // ML-DSA-87
		var pub mode5.PublicKey
		if err := pub.UnmarshalBinary(pubBytes); err != nil {
			return symmetric.CryptoResult{Error: "解析公钥失败: " + err.Error()}
		}
		scheme := mode5.Scheme()
		valid := scheme.Verify(&pub, msgBytes, sigBytes, nil)
		if !valid {
			return symmetric.CryptoResult{Success: true, Data: "false", Error: "签名验证失败"}
		}
	}
	return symmetric.CryptoResult{Success: true, Data: "true"}
}

// ============================================================
// SLH-DSA (SPHINCS+) — FIPS 205
// ============================================================

type SLHDSARequest struct {
	PrivateKey string `json:"privateKey"`
	Data       string `json:"data"`
	ParamSet   string `json:"paramSet"`
}

type SLHDSAVerifyRequest struct {
	PublicKey string `json:"publicKey"`
	Data      string `json:"data"`
	Signature string `json:"signature"`
	ParamSet  string `json:"paramSet"`
}

func SLHDSAKeyGen(paramSet string) PQCKeyResult {
	id, err := slhdsa.IDByName(paramSet)
	if err != nil {
		return PQCKeyResult{
			Success:  false,
			Error:    "不支持的 SLH-DSA 参数集: " + err.Error(),
			ParamSet: paramSet,
		}
	}

	pub, priv, err := slhdsa.GenerateKey(rand.Reader, id)
	if err != nil {
		return PQCKeyResult{
			Success:  false,
			Error:    "SLH-DSA 密钥生成失败: " + err.Error(),
			ParamSet: paramSet,
		}
	}
	pubBytes, _ := pub.MarshalBinary()
	privBytes, _ := priv.MarshalBinary()
	return PQCKeyResult{
		Success:    true,
		PublicKey:  hexUpper(pubBytes),
		PrivateKey: hexUpper(privBytes),
		ParamSet:   paramSet,
	}
}

func SLHDSASign(req SLHDSARequest) symmetric.CryptoResult {
	privBytes, err := hex.DecodeString(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的私钥: " + err.Error()}
	}
	msgBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	id, err := slhdsa.IDByName(req.ParamSet)
	if err != nil {
		return symmetric.CryptoResult{Error: "不支持的 SLH-DSA 参数集: " + err.Error()}
	}

	priv := slhdsa.PrivateKey{ID: id}
	if err := priv.UnmarshalBinary(privBytes); err != nil {
		return symmetric.CryptoResult{Error: "解析 SLH-DSA 私钥失败: " + err.Error()}
	}

	sig, err := priv.Sign(rand.Reader, msgBytes, nil)
	if err != nil {
		return symmetric.CryptoResult{Error: "SLH-DSA 签名失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}
}

func SLHDSAVerify(req SLHDSAVerifyRequest) symmetric.CryptoResult {
	pubBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效公钥: " + err.Error()}
	}
	msgBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效数据: " + err.Error()}
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效签名: " + err.Error()}
	}

	id, err := slhdsa.IDByName(req.ParamSet)
	if err != nil {
		return symmetric.CryptoResult{Error: "不支持的 SLH-DSA 参数集: " + err.Error()}
	}

	pub := slhdsa.PublicKey{ID: id}
	if err := pub.UnmarshalBinary(pubBytes); err != nil {
		return symmetric.CryptoResult{Error: "解析 SLH-DSA 公钥失败: " + err.Error()}
	}

	ok := slhdsa.Verify(&pub, slhdsa.NewMessage(msgBytes), sigBytes, nil)
	if !ok {
		return symmetric.CryptoResult{Success: true, Data: "false", Error: "签名验证失败"}
	}
	return symmetric.CryptoResult{Success: true, Data: "true"}
}
