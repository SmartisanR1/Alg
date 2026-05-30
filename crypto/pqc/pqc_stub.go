//go:build !oqs
// +build !oqs

package pqc

import "cryptokit/crypto/symmetric"

// FALCON — circl v1.6.3 不包含 Falcon 实现，需等待 FIPS 206 正式发布后 circl 跟进
func FalconKeyGen(paramSet string) PQCKeyResult {
	return PQCKeyResult{Error: "FALCON 暂无纯 Go 实现 (circl v1.6.3 未包含)，等待 FIPS 206 标准正式发布"}
}
func FalconSign(req SLHDSARequest) symmetric.CryptoResult {
	return symmetric.CryptoResult{Error: "FALCON 暂无纯 Go 实现"}
}
func FalconVerify(req SLHDSAVerifyRequest) symmetric.CryptoResult {
	return symmetric.CryptoResult{Error: "FALCON 暂无纯 Go 实现"}
}

// HQC — 纯 Go 实现不可用，circl 不包含 HQC
func HQCKeyGen(paramSet string) PQCKeyResult {
	return PQCKeyResult{Error: "HQC 暂无纯 Go 实现，NIST 标准化进行中 (预计 2025-2026)"}
}
func HQCEncapsulate(req MLKEMRequest) PQCEncapResult {
	return PQCEncapResult{Error: "HQC 暂无纯 Go 实现"}
}
func HQCDecapsulate(req MLKEMDecapRequest) symmetric.CryptoResult {
	return symmetric.CryptoResult{Error: "HQC 暂无纯 Go 实现"}
}
