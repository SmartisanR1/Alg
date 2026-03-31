package main

import (
	"context"
	"cryptokit/crypto/asymmetric"
	"cryptokit/crypto/finance"
	"cryptokit/crypto/gm"
	"cryptokit/crypto/hash"
	"cryptokit/crypto/kdf"
	"cryptokit/crypto/mac"
	"cryptokit/crypto/pqc"
	"cryptokit/crypto/symmetric"
	"cryptokit/crypto/utils"
	"os"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) domReady(ctx context.Context) {
	// StartHidden=true 模式：前端就绪后立即展示完整界面
	// 避免 Windows 下 WebView2 初始化阶段用户看到空白窗口
	runtime.WindowShow(ctx)
}

func (a *App) beforeClose(ctx context.Context) (prevent bool) {
	return false
}

func (a *App) shutdown(ctx context.Context) {}

// ============================================================
// 对称加密 API
// ============================================================

func (a *App) AESEncrypt(req symmetric.AESRequest) symmetric.CryptoResult {
	return symmetric.AESEncrypt(req)
}

func (a *App) AESDecrypt(req symmetric.AESRequest) symmetric.CryptoResult {
	return symmetric.AESDecrypt(req)
}

func (a *App) DESEncrypt(req symmetric.DESRequest) symmetric.CryptoResult {
	return symmetric.DESEncrypt(req)
}

func (a *App) DESDecrypt(req symmetric.DESRequest) symmetric.CryptoResult {
	return symmetric.DESDecrypt(req)
}

func (a *App) ChaCha20Encrypt(req symmetric.ChaChaRequest) symmetric.CryptoResult {
	return symmetric.ChaCha20Encrypt(req)
}

func (a *App) ChaCha20Decrypt(req symmetric.ChaChaRequest) symmetric.CryptoResult {
	return symmetric.ChaCha20Decrypt(req)
}

func (a *App) RC4Encrypt(req symmetric.RC4Request) symmetric.CryptoResult {
	return symmetric.RC4Encrypt(req)
}

func (a *App) RC4Decrypt(req symmetric.RC4Request) symmetric.CryptoResult {
	return symmetric.RC4Decrypt(req)
}

func (a *App) SIVEncrypt(req symmetric.SIVRequest) symmetric.CryptoResult {
	return symmetric.SIVEncrypt(req)
}

func (a *App) SIVDecrypt(req symmetric.SIVRequest) symmetric.CryptoResult {
	return symmetric.SIVDecrypt(req)
}

func (a *App) FPEEncrypt(req symmetric.FPERequest) symmetric.CryptoResult {
	return symmetric.FPEEncrypt(req)
}

func (a *App) FPEDecrypt(req symmetric.FPERequest) symmetric.CryptoResult {
	return symmetric.FPEDecrypt(req)
}

// ============================================================
// 非对称加密 API
// ============================================================

func (a *App) RSAGenerateKey(bits int) asymmetric.KeyPairResult {
	return asymmetric.RSAGenerateKey(bits)
}

func (a *App) RSAEncrypt(req asymmetric.RSARequest) symmetric.CryptoResult {
	return asymmetric.RSAEncrypt(req)
}

func (a *App) RSADecrypt(req asymmetric.RSARequest) symmetric.CryptoResult {
	return asymmetric.RSADecrypt(req)
}

func (a *App) RSASign(req asymmetric.RSASignRequest) symmetric.CryptoResult {
	return asymmetric.RSASign(req)
}

func (a *App) RSAVerify(req asymmetric.RSAVerifyRequest) symmetric.CryptoResult {
	return asymmetric.RSAVerify(req)
}

func (a *App) ECCGenerateKey(curve string) asymmetric.KeyPairResult {
	return asymmetric.ECCGenerateKey(curve)
}

func (a *App) ECCSign(req asymmetric.ECCRequest) symmetric.CryptoResult {
	return asymmetric.ECCSign(req)
}

func (a *App) ECCVerify(req asymmetric.ECCVerifyRequest) symmetric.CryptoResult {
	return asymmetric.ECCVerify(req)
}

func (a *App) ECDHCompute(req asymmetric.ECDHRequest) symmetric.CryptoResult {
	return asymmetric.ECDHCompute(req)
}

func (a *App) X25519KeyGen() asymmetric.KeyPairResult {
	return asymmetric.X25519KeyGen()
}

func (a *App) X25519Exchange(req asymmetric.X25519Request) symmetric.CryptoResult {
	return asymmetric.X25519Exchange(req)
}

func (a *App) Ed25519KeyGen() asymmetric.KeyPairResult {
	return asymmetric.Ed25519KeyGen()
}

func (a *App) Ed25519Sign(req asymmetric.EdDSARequest) symmetric.CryptoResult {
	return asymmetric.Ed25519Sign(req)
}

func (a *App) Ed25519Verify(req asymmetric.EdDSAVerifyRequest) symmetric.CryptoResult {
	return asymmetric.Ed25519Verify(req)
}

func (a *App) Ed448KeyGen() asymmetric.KeyPairResult {
	return asymmetric.Ed448KeyGen()
}

func (a *App) Ed448Sign(req asymmetric.Ed448Request) symmetric.CryptoResult {
	return asymmetric.Ed448Sign(req)
}

func (a *App) Ed448Verify(req asymmetric.Ed448VerifyRequest) symmetric.CryptoResult {
	return asymmetric.Ed448Verify(req)
}

// ============================================================
// 哈希 / HMAC API
// ============================================================

func (a *App) Hash(req hash.HashRequest) symmetric.CryptoResult {
	return hash.Compute(req)
}

func (a *App) HMAC(req hash.HMACRequest) symmetric.CryptoResult {
	return hash.ComputeHMAC(req)
}

// ============================================================
// MAC API
// ============================================================

func (a *App) ComputeMAC(req mac.MACRequest) symmetric.CryptoResult {
	return mac.Compute(req)
}

// ============================================================
// 金融密码 API
// ============================================================

func (a *App) RetailMAC(req finance.RetailMACRequest) symmetric.CryptoResult {
	return finance.RetailMAC(req)
}

func (a *App) GeneratePINBlock(req finance.PINBlockRequest) finance.PINBlockResult {
	return finance.GeneratePINBlock(req)
}

func (a *App) ParsePINBlock(req finance.PINBlockParseRequest) finance.PINParseResult {
	return finance.ParsePINBlock(req)
}

func (a *App) EncryptPINBlock(req finance.PINEncryptRequest) symmetric.CryptoResult {
	return finance.EncryptPINBlock(req)
}

func (a *App) DecryptPINBlock(req finance.PINEncryptRequest) symmetric.CryptoResult {
	return finance.DecryptPINBlock(req)
}

func (a *App) ComputePVV(req finance.PVVRequest) finance.PVVResult {
	return finance.ComputePVV(req)
}

func (a *App) ComputeCVV(req finance.CVVRequest) finance.CVVResult {
	return finance.ComputeCVV(req)
}

func (a *App) DeriveEMVUDK(req finance.UDKRequest) finance.UDKResult {
	return finance.DeriveEMVUDK(req)
}

func (a *App) DoubleOneWay(req finance.DOWRequest) finance.DOWResult {
	return finance.DoubleOneWay(req)
}

func (a *App) ComputeARQC(req finance.EMVACRequest) symmetric.CryptoResult {
	return finance.ComputeARQC(req)
}

func (a *App) TDESEncrypt(req finance.TDESRequest) symmetric.CryptoResult {
	return finance.TDESEncrypt(req)
}

func (a *App) TDESDecrypt(req finance.TDESRequest) symmetric.CryptoResult {
	return finance.TDESDecrypt(req)
}

func (a *App) SM4MAC(req finance.SM4MACRequest) symmetric.CryptoResult {
	return finance.SM4MAC(req)
}

func (a *App) SM4EncryptFinance(req finance.SM4FinanceRequest) symmetric.CryptoResult {
	return finance.SM4EncryptFinance(req)
}

func (a *App) SM4DecryptFinance(req finance.SM4FinanceRequest) symmetric.CryptoResult {
	return finance.SM4DecryptFinance(req)
}

func (a *App) SM4CMAC(req finance.SM4CMACRequest) symmetric.CryptoResult {
	return finance.SM4CMAC(req)
}

func (a *App) SM2EncryptPIN(req finance.SM2PINRequest) symmetric.CryptoResult {
	return finance.SM2EncryptPIN(req)
}

func (a *App) SM2DecryptPIN(req finance.SM2PINRequest) symmetric.CryptoResult {
	return finance.SM2DecryptPIN(req)
}

func (a *App) SM4EncryptPIN(req finance.SM4PINRequest) symmetric.CryptoResult {
	return finance.SM4EncryptPIN(req)
}

func (a *App) SM4DecryptPIN(req finance.SM4PINRequest) symmetric.CryptoResult {
	return finance.SM4DecryptPIN(req)
}

func (a *App) DeriveSM4UDK(req finance.SM4UDKRequest) finance.UDKResult {
	return finance.DeriveSM4UDK(req)
}

// ============================================================
// KDF API
// ============================================================

func (a *App) DeriveKey(req kdf.KDFRequest) symmetric.CryptoResult {
	return kdf.Derive(req)
}

// ============================================================
// 国密算法 API
// ============================================================

func (a *App) SM2GenerateKey() gm.SM2KeyResult {
	return gm.SM2GenerateKey()
}

func (a *App) SM2Encrypt(req gm.SM2Request) symmetric.CryptoResult {
	return gm.SM2Encrypt(req)
}

func (a *App) SM2Decrypt(req gm.SM2Request) symmetric.CryptoResult {
	return gm.SM2Decrypt(req)
}

func (a *App) SM2Sign(req gm.SM2SignRequest) symmetric.CryptoResult {
	return gm.SM2Sign(req)
}

func (a *App) SM2Verify(req gm.SM2VerifyRequest) symmetric.CryptoResult {
	return gm.SM2Verify(req)
}

func (a *App) SM2KeyAgreement(req gm.SM2KeyAgreementRequest) symmetric.CryptoResult {
	return gm.SM2KeyAgreement(req)
}

func (a *App) SM3Hash(req gm.SM3Request) symmetric.CryptoResult {
	return gm.SM3Hash(req)
}

func (a *App) SM3HMAC(req gm.SM3HMACRequest) symmetric.CryptoResult {
	return gm.SM3HMAC(req)
}

func (a *App) SM4Encrypt(req gm.SM4Request) symmetric.CryptoResult {
	return gm.SM4Encrypt(req)
}

func (a *App) SM4Decrypt(req gm.SM4Request) symmetric.CryptoResult {
	return gm.SM4Decrypt(req)
}

func (a *App) SM9GenerateEncKey(masterPub string, uid string) gm.SM9KeyResult {
	return gm.SM9GenerateEncKey(masterPub, uid)
}

func (a *App) SM9Encrypt(req gm.SM9Request) symmetric.CryptoResult {
	return gm.SM9Encrypt(req)
}

func (a *App) SM9Decrypt(req gm.SM9Request) symmetric.CryptoResult {
	return gm.SM9Decrypt(req)
}

func (a *App) SM9GenerateMasterKey() gm.SM9MasterKeyResult {
	return gm.SM9GenerateMasterKey()
}

func (a *App) SM9Sign(req gm.SM9SignRequest) symmetric.CryptoResult {
	return gm.SM9Sign(req)
}

func (a *App) SM9Verify(req gm.SM9VerifyRequest) symmetric.CryptoResult {
	return gm.SM9Verify(req)
}

func (a *App) ZUCEncrypt(req gm.ZUCRequest) symmetric.CryptoResult {
	return gm.ZUCEncrypt(req)
}

func (a *App) ZUCDecrypt(req gm.ZUCRequest) symmetric.CryptoResult {
	return gm.ZUCDecrypt(req)
}

func (a *App) MakeGMEnvelope(req gm.GMEnvelopeRequest) symmetric.CryptoResult {
	return gm.MakeGMEnvelope(req)
}

func (a *App) OpenGMEnvelope(req gm.GMEnvelopeOpenRequest) symmetric.CryptoResult {
	return gm.OpenGMEnvelope(req)
}

// ============================================================
// 后量子密码 API
// ============================================================

func (a *App) MLKEMKeyGen(paramSet string) pqc.PQCKeyResult {
	return pqc.MLKEMKeyGen(paramSet)
}

func (a *App) MLKEMEncapsulate(req pqc.MLKEMRequest) pqc.PQCEncapResult {
	return pqc.MLKEMEncapsulate(req)
}

func (a *App) MLKEMDecapsulate(req pqc.MLKEMDecapRequest) symmetric.CryptoResult {
	return pqc.MLKEMDecapsulate(req)
}

func (a *App) MLDSAKeyGen(paramSet string) pqc.PQCKeyResult {
	return pqc.MLDSAKeyGen(paramSet)
}

func (a *App) MLDSASign(req pqc.MLDSARequest) symmetric.CryptoResult {
	return pqc.MLDSASign(req)
}

func (a *App) MLDSAVerify(req pqc.MLDSAVerifyRequest) symmetric.CryptoResult {
	return pqc.MLDSAVerify(req)
}

func (a *App) SLHDSAKeyGen(paramSet string) pqc.PQCKeyResult {
	return pqc.SLHDSAKeyGen(paramSet)
}

func (a *App) SLHDSASign(req pqc.SLHDSARequest) symmetric.CryptoResult {
	return pqc.SLHDSASign(req)
}

func (a *App) SLHDSAVerify(req pqc.SLHDSAVerifyRequest) symmetric.CryptoResult {
	return pqc.SLHDSAVerify(req)
}

// ============================================================
// 工具 API
// ============================================================

func (a *App) HexToString(hex string) utils.ToolResult {
	return utils.HexToString(hex)
}

func (a *App) StringToHex(str string) utils.ToolResult {
	return utils.StringToHex(str)
}

func (a *App) Base64Encode(req utils.Base64Request) utils.ToolResult {
	return utils.Base64Encode(req)
}

func (a *App) Base64Decode(req utils.Base64Request) utils.ToolResult {
	return utils.Base64Decode(req)
}

func (a *App) XORCompute(req utils.XORRequest) utils.ToolResult {
	return utils.XORCompute(req)
}

func (a *App) URLEncode(str string) utils.ToolResult {
	return utils.URLEncode(str)
}

func (a *App) URLDecode(str string) utils.ToolResult {
	return utils.URLDecode(str)
}

func (a *App) GenerateRandom(req utils.RandomRequest) utils.ToolResult {
	return utils.GenerateRandom(req)
}

func (a *App) PaddingApply(req utils.PaddingRequest) utils.ToolResult {
	return utils.PaddingApply(req)
}

func (a *App) PaddingRemove(req utils.PaddingRequest) utils.ToolResult {
	return utils.PaddingRemove(req)
}

func (a *App) FormatJSON(str string) utils.ToolResult {
	return utils.FormatJSON(str)
}

func (a *App) TimestampConvert(req utils.TimestampRequest) utils.ToolResult {
	return utils.TimestampConvert(req)
}

func (a *App) UnicodeEncode(str string) utils.ToolResult {
	return utils.UnicodeEncode(str)
}

func (a *App) UnicodeDecode(str string) utils.ToolResult {
	return utils.UnicodeDecode(str)
}

func (a *App) BaseConvert(req utils.BaseConvertRequest) utils.ToolResult {
	return utils.BaseConvert(req)
}

func (a *App) ParseASN1(req utils.ASN1Request) utils.ToolResult {
	return utils.ParseASN1(req)
}

func (a *App) ParseASN1File(path string) utils.ToolResult {
	return utils.ParseASN1File(path)
}

func (a *App) Base32Encode(req utils.Base32Request) utils.ToolResult {
	return utils.Base32Encode(req)
}

func (a *App) Base32Decode(req utils.Base32Request) utils.ToolResult {
	return utils.Base32Decode(req)
}

func (a *App) Base58Encode(req utils.Base58Request) utils.ToolResult {
	return utils.Base58Encode(req)
}

func (a *App) Base58Decode(req utils.Base58Request) utils.ToolResult {
	return utils.Base58Decode(req)
}

func (a *App) Bech32Encode(req utils.Bech32EncodeRequest) utils.ToolResult {
	return utils.Bech32Encode(req)
}

func (a *App) Bech32Decode(input string) utils.Bech32DecodeResult {
	return utils.Bech32Decode(input)
}

func (a *App) ParseJWT(req utils.JWTRequest) utils.JWTResult {
	return utils.ParseJWT(req)
}

func (a *App) ConvertKey(req utils.KeyConvertRequest) utils.KeyConvertResult {
	return utils.ConvertKey(req)
}

func (a *App) VerifyCertChain(req utils.CertChainRequest) utils.CertChainResult {
	return utils.VerifyCertChain(req)
}

func (a *App) ParsePKCS12(req utils.PKCS12Request) utils.PKCS12Result {
	return utils.ParsePKCS12(req)
}

func (a *App) ParsePKCS12File(path string, password string) utils.PKCS12Result {
	return utils.ParsePKCS12File(path, password)
}

func (a *App) SendPacket(req utils.PacketIORequest) utils.PacketIOResult {
	return utils.SendPacket(req)
}

func (a *App) SelectFile() string {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择文件",
	})
	if err != nil {
		return ""
	}
	return path
}

func (a *App) SaveFile(content string, filename string) bool {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "保存文件",
		DefaultFilename: filename,
	})
	if err != nil || path == "" {
		return false
	}
	err = os.WriteFile(path, []byte(content), 0644)
	return err == nil
}

func (a *App) HashFile(req utils.FileHashRequest) utils.ToolResult {
	return utils.HashFile(req)
}

func (a *App) EncryptFile(req utils.FileEncryptRequest) utils.ToolResult {
	return utils.EncryptFile(req)
}

func (a *App) DecryptFile(req utils.FileDecryptRequest) utils.ToolResult {
	return utils.DecryptFile(req)
}

// ============================================================
// 大数运算 & 证书 API
// ============================================================

func (a *App) BigIntOperation(req utils.BigIntRequest) utils.ToolResult {
	return utils.BigIntOperation(req)
}

func (a *App) GenerateCSR(req utils.CSRRequest) utils.ToolResult {
	return utils.GenerateCSR(req)
}

func (a *App) GenerateCertificate(req utils.CertGenRequest) utils.ToolResult {
	return utils.GenerateCertificate(req)
}

func (a *App) GenerateSelfSignedCert(req utils.SelfSignedCertRequest) utils.SelfSignedCertResult {
	return utils.GenerateSelfSignedCert(req)
}

func (a *App) GenerateInternalSignedCert(req utils.SelfSignedCertRequest) utils.InternalCAResult {
	return utils.GenerateInternalSignedCert(req)
}

func (a *App) GenerateDualCertificates(req utils.SelfSignedCertRequest) utils.DualCertResult {
	return utils.GenerateDualCertificates(req)
}

func (a *App) GetInternalRootCert(algo string) string {
	return utils.GetInternalRootCert(algo)
}

func (a *App) ParseCertificate(pemStr string) utils.ToolResult {
	return utils.ParseCertificate(pemStr)
}

func (a *App) ReadFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// ============================================================
// 额外 PQC API
// ============================================================

func (a *App) FalconKeyGen(paramSet string) pqc.PQCKeyResult {
	return pqc.FalconKeyGen(paramSet)
}

func (a *App) FalconSign(req pqc.SLHDSARequest) symmetric.CryptoResult {
	return pqc.FalconSign(req)
}

func (a *App) FalconVerify(req pqc.SLHDSAVerifyRequest) symmetric.CryptoResult {
	return pqc.FalconVerify(req)
}

func (a *App) HQCKeyGen(paramSet string) pqc.PQCKeyResult {
	return pqc.HQCKeyGen(paramSet)
}

func (a *App) AigisKeyGen(paramSet string) pqc.PQCKeyResult {
	return pqc.AigisKeyGen(paramSet)
}

func (a *App) AigisSign(req pqc.SLHDSARequest) symmetric.CryptoResult {
	return pqc.AigisSign(req)
}

func (a *App) AigisVerify(req pqc.SLHDSAVerifyRequest) symmetric.CryptoResult {
	return pqc.AigisVerify(req)
}

func (a *App) HQCEncapsulate(req pqc.MLKEMRequest) pqc.PQCEncapResult {
	return pqc.HQCEncapsulate(req)
}

func (a *App) HQCDecapsulate(req pqc.MLKEMDecapRequest) symmetric.CryptoResult {
	return pqc.HQCDecapsulate(req)
}
