//go:build !oqs
// +build !oqs

// pqc_stub.go — 在未启用 oqs 构建标签时提供占位实现。
// 启用真实 liboqs 集成: go build -tags oqs ./...

package pqc

import "cryptokit/crypto/symmetric"

// FALCON — NTRU格紧凑签名 (FIPS 206)
// circl 1.6.3 尚未正式导出 Falcon 的标准 FIPS 实现 API
func FalconKeyGen(paramSet string) PQCKeyResult {
	return PQCKeyResult{Error: "__ADAPTING_FIPS_206__"}
}
func FalconSign(req SLHDSARequest) symmetric.CryptoResult {
	return symmetric.CryptoResult{Error: "__ADAPTING_FIPS_206__"}
}
func FalconVerify(req SLHDSAVerifyRequest) symmetric.CryptoResult {
	return symmetric.CryptoResult{Error: "__ADAPTING_FIPS_206__"}
}

// HQC — 准循环码密钥封装 (NIST Round 4)
func HQCKeyGen(paramSet string) PQCKeyResult {
	return PQCKeyResult{Error: "__AWAITING_STABLE_IMPLEMENTATION__"}
}
func HQCEncapsulate(req MLKEMRequest) PQCEncapResult {
	return PQCEncapResult{Error: "__AWAITING_STABLE_IMPLEMENTATION__"}
}
func HQCDecapsulate(req MLKEMDecapRequest) symmetric.CryptoResult {
	return symmetric.CryptoResult{Error: "__AWAITING_STABLE_IMPLEMENTATION__"}
}
