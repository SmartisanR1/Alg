//go:build !oqs
// +build !oqs

// pqc_stub.go — 在未启用 oqs 构建标签时提供占位实现。
// 启用真实 liboqs 集成: go build -tags oqs ./...

package pqc

import "cryptokit/crypto/symmetric"

// FALCON — NTRU格紧凑签名，目前无成熟纯Go实现
// 后端返回特殊标记 "__NOT_IMPLEMENTED__" 供前端识别并展示友好UI
func FalconKeyGen(paramSet string) PQCKeyResult {
	return PQCKeyResult{Error: "__NOT_IMPLEMENTED__"}
}
func FalconSign(req SLHDSARequest) symmetric.CryptoResult {
	return symmetric.CryptoResult{Error: "__NOT_IMPLEMENTED__"}
}
func FalconVerify(req SLHDSAVerifyRequest) symmetric.CryptoResult {
	return symmetric.CryptoResult{Error: "__NOT_IMPLEMENTED__"}
}

// HQC — 准循环码KEM，目前无成熟纯Go实现
func HQCKeyGen(paramSet string) PQCKeyResult {
	return PQCKeyResult{Error: "__NOT_IMPLEMENTED__"}
}
func HQCEncapsulate(req MLKEMRequest) PQCEncapResult {
	return PQCEncapResult{Error: "__NOT_IMPLEMENTED__"}
}
func HQCDecapsulate(req MLKEMDecapRequest) symmetric.CryptoResult {
	return symmetric.CryptoResult{Error: "__NOT_IMPLEMENTED__"}
}
