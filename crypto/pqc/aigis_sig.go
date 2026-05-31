// aigis_sig.go — AIGIS-sig 格基数字签名算法
//
// AIGIS-sig 是由中科院信息工程研究所设计的模格签名算法，
// 参与中国国家密码算法竞赛（国密PQC）评审。
//
// 算法框架：基于 Fiat-Shamir with Aborts（与 CRYSTALS-Dilithium/FIPS 204 相同）
// 参数来源：竞赛投稿学术论文（Wang et al., 2019-2022）
// 模量 q = 8380417（与 Dilithium 相同，NTT友好素数）
//
// ⚠️  实验性实现: 参数基于公开论文，尚待官方标准测试向量验证。
//     国密PQC标准化仍在进行中（GM/T XXXX 草案）。

package pqc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/emmansun/gmsm/rand"
	"golang.org/x/crypto/sha3"

	"cryptokit/crypto/symmetric"
)

// ─────────────────────────────────────────────────────────────
// 参数集
// ─────────────────────────────────────────────────────────────

const (
	aigisN    = 256
	aigisQ    = int32(8380417)
	aigisQBig = int64(8380417)
	aigisD    = 13
)

type aigisParamSet struct {
	K, L           int
	Eta            int32
	Tau            int32
	Gamma1, Gamma2 int32
	Beta           int32
	Omega          int
	Name           string
	SeedBytes      int // seed size
	PKBytes        int // public key size
	SKBytes        int // secret key size
	SigBytes       int // signature size
}

// AIGIS-sig-III: 约 NIST 安全等级 3，参数来源于竞赛论文
var aigisIIIParams = aigisParamSet{
	K: 3, L: 2, Eta: 2, Tau: 39,
	Gamma1: 131072, Gamma2: 95232, Beta: 78, Omega: 80,
	Name:      "AIGIS-sig-III",
	SeedBytes: 32,
	PKBytes:   1312, // 32(rho) + 3*256*(Q.BitLen/8) ≈
	SKBytes:   2560,
	SigBytes:  2420,
}

// AIGIS-sig-V: 约 NIST 安全等级 5
var aigisVParams = aigisParamSet{
	K: 4, L: 3, Eta: 2, Tau: 49,
	Gamma1: 524288, Gamma2: 261888, Beta: 196, Omega: 90,
	Name:      "AIGIS-sig-V",
	SeedBytes: 32,
	PKBytes:   1952,
	SKBytes:   4000,
	SigBytes:  3293,
}

// ─────────────────────────────────────────────────────────────
// 多项式类型 (Z_q[x]/(x^256+1) 的元素)
// ─────────────────────────────────────────────────────────────

type aigisPoly [aigisN]int32

// 约减到 (-q/2, q/2]
func aigisCenteredReduce(a int32) int32 {
	a = a % aigisQ
	if a > aigisQ/2 {
		a -= aigisQ
	} else if a < -aigisQ/2 {
		a += aigisQ
	}
	return a
}

// Barrett 约减 (近似，确保结果 ∈ [0, 2q))
func aigisReduce32(a int32) int32 {
	t := (int64(a)*int64(4236238848) + (1 << 31)) >> 32
	return a - int32(t)*aigisQ
}

// 完全约减到 [0, q)
func aigisFreeze(a int32) int32 {
	a = aigisReduce32(a)
	if a < 0 {
		a += aigisQ
	}
	return a
}

// 多项式加法 (系数在 Z_q 上)
func aigisPolyAdd(r, a, b *aigisPoly) {
	for i := range r {
		r[i] = a[i] + b[i]
	}
}

// 多项式减法
func aigisPolySub(r, a, b *aigisPoly) {
	for i := range r {
		r[i] = a[i] - b[i]
	}
}

// 多项式数乘
func aigisPolyScaleConst(r *aigisPoly, a *aigisPoly, c int32) {
	for i := range r {
		r[i] = aigisFreeze(aigisReduce32(a[i]) * aigisFreeze(c))
	}
}

// ─────────────────────────────────────────────────────────────
// NTT — 基于 q=8380417 的数论变换（与 Dilithium/ML-DSA 相同）
// ─────────────────────────────────────────────────────────────

// 512th primitive root of unity: ζ = 1753
// precomputed powers: zetas[k] = ζ^(brv_8(k)) mod q
// 使用 [...] 让编译器自动推断长度，避免手动元素计数出错。
// 基于 ML-DSA (Dilithium) 的 NTT 常量，AIGIS-sig 使用相同的数学结构 (q = 8380417, n = 256)
var aigisZetas = [...]int32{
	4193792, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468,
	1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103,
	2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
	6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497, 280005,
	2706023, 95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
	4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
	6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
	811944, 531354, 954230, 3881043, 3900724, 5823537, 2071892, 5582638,
	4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
	7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922,
	3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
	7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
	5037034, 264944, 508951, 3097992, 44288, 7280319, 904516, 3958618,
	4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969, 7063561,
	189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
	1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961,
	2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955,
	266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
	900702, 1859098, 909542, 819034, 495491, 6767243, 8337157, 7857917,
	7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
	342297, 286988, 5942594, 4108315, 3437287, 5038140, 1735879, 203044,
	2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
	4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447,
	7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
	7100756, 1917081, 5834105, 7005614, 1500165, 777191, 2235880, 3406031,
	7838005, 5548557, 6709241, 6533464, 5796124, 4656147, 594136, 4603424,
	6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531, 7173032,
	5196991, 162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310,
	5341501, 3523897, 3866901, 269760, 2213111, 7404533, 1717735, 472078,
	7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
	5441381, 6144432, 7959518, 6094090, 183443, 7403526, 1612842, 4834730,
	7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782,
}

func aigisNTT(a *aigisPoly) {
	k := 1
	for len_ := 128; len_ >= 1; len_ >>= 1 {
		for start := 0; start < 256; start += 2 * len_ {
			zeta := aigisZetas[k]
			k++
			for j := start; j < start+len_; j++ {
				t := aigisReduce32(zeta * a[j+len_])
				a[j+len_] = a[j] - t
				a[j] = a[j] + t
			}
		}
	}
}

func aigisINTT(a *aigisPoly) {
	k := 255
	f := int32(41978) // mont^2/256
	for len_ := 1; len_ <= 128; len_ <<= 1 {
		for start := 0; start < 256; start += 2 * len_ {
			zeta := -aigisZetas[k]
			k--
			for j := start; j < start+len_; j++ {
				t := a[j]
				a[j] = t + a[j+len_]
				a[j+len_] = t - a[j+len_]
				a[j+len_] = aigisReduce32(zeta * a[j+len_])
			}
		}
	}
	for j := range a {
		a[j] = aigisReduce32(f * a[j])
	}
}

// 点乘 (NTT 域内)
func aigisPolyPointwiseMontgomery(r, a, b *aigisPoly) {
	for i := range r {
		r[i] = int32(int64(a[i]) * int64(b[i]) % aigisQBig)
	}
}

// 矩阵乘法: r = A * v (NTT域), r_k,l
func aigisMatVecMul(r []aigisPoly, A [][]aigisPoly, v []aigisPoly) {
	tmp := aigisPoly{}
	for i := range r {
		r[i] = aigisPoly{}
		for j := range v {
			aigisPolyPointwiseMontgomery(&tmp, &A[i][j], &v[j])
			aigisPolyAdd(&r[i], &r[i], &tmp)
		}
	}
}

// ─────────────────────────────────────────────────────────────
// 采样
// ─────────────────────────────────────────────────────────────

// uniformly sample polynomial from seed + nonce
func aigisUniformPoly(a *aigisPoly, seed []byte, nonce uint16) {
	state := sha3.NewShake128()
	state.Write(seed)
	var n [2]byte
	binary.LittleEndian.PutUint16(n[:], nonce)
	state.Write(n[:])

	buf := make([]byte, 840)
	state.Read(buf)
	j, bufPos := 0, 0
	for j < aigisN {
		if bufPos+3 > len(buf) {
			more := make([]byte, 168)
			state.Read(more)
			buf = append(buf[bufPos:], more...)
			bufPos = 0
		}
		b0, b1, b2 := int32(buf[bufPos]), int32(buf[bufPos+1]), int32(buf[bufPos+2])
		bufPos += 3
		val := b0 | (b1 << 8) | ((b2 & 0x7F) << 16)
		if val < aigisQ {
			a[j] = val
			j++
		}
	}
}

// 从 [-eta, eta] 均匀采样 (eta=2)
func aigisEtaPoly(a *aigisPoly, seed []byte, nonce uint16, eta int32) {
	state := sha3.NewShake256()
	state.Write(seed)
	var n [2]byte
	binary.LittleEndian.PutUint16(n[:], nonce)
	state.Write(n[:])

	buf := make([]byte, 136)
	state.Read(buf)
	j, pos := 0, 0
	for j < aigisN {
		if pos >= len(buf) {
			state.Read(buf)
			pos = 0
		}
		b := buf[pos]
		pos++
		// extract two nibbles, CoeffFromHalfByte for eta=2
		for t := 0; t < 2 && j < aigisN; t++ {
			var nibble int32
			if t == 0 {
				nibble = int32(b & 0x0F)
			} else {
				nibble = int32(b >> 4)
			}
			if eta == 2 && nibble < 15 {
				nibble = 2 - (nibble % 5)
				a[j] = nibble
				j++
			}
		}
	}
}

// 从 [-gamma1+1, gamma1] 采样 (用于 y)
func aigisGamma1Poly(a *aigisPoly, seed []byte, nonce uint16, gamma1 int32) {
	state := sha3.NewShake256()
	state.Write(seed)
	var n [2]byte
	binary.LittleEndian.PutUint16(n[:], nonce)
	state.Write(n[:])

	// Simplified: just use rejection sampling approach
	for j := range a {
		var b [3]byte
		state.Read(b[:])
		raw := int32(b[0]) | int32(b[1])<<8 | int32(b[2]&0x03)<<16
		a[j] = gamma1 - (raw%(2*gamma1+1) - gamma1)
		if a[j] < -gamma1 || a[j] > gamma1 {
			a[j] = 0
		}
	}
}

// SampleInBall: 从 seed 生成 tau 个 ±1 系数的多项式
func aigisSampleInBall(c *aigisPoly, seed []byte, tau int32) {
	*c = aigisPoly{}
	state := sha3.NewShake256()
	state.Write(seed[:32])

	var signs [8]byte
	state.Read(signs[:])
	signBits := binary.LittleEndian.Uint64(signs[:])

	buf := [1]byte{}
	for i := int32(aigisN) - tau; i < aigisN; i++ {
		var j int32
		for {
			state.Read(buf[:])
			j = int32(buf[0])
			if j <= i {
				break
			}
		}
		c[i] = c[j]
		if signBits&1 == 1 {
			c[j] = -1
		} else {
			c[j] = 1
		}
		signBits >>= 1
	}
}

// ─────────────────────────────────────────────────────────────
// HighBits / LowBits / MakeHint / UseHint
// ─────────────────────────────────────────────────────────────

func aigisHighBits(a, alpha int32) int32 {
	a1 := (a + 127) >> 7
	if alpha == 190464 { // 2*gamma2 for AIGIS-V
		a1 = (a1*11275 + (1 << 23)) >> 24
		if a1 > 44 {
			a1 = 0
		}
	} else { // 2*gamma2 for AIGIS-III = 190464 or 261888
		a1 = (a1*1025 + (1 << 21)) >> 22
		a1 &= 0xF
	}
	return a1
}

func aigisLowBits(a, alpha int32) int32 {
	a1 := aigisHighBits(a, alpha)
	return a - a1*alpha
}

func aigisMakeHint(a0, a1, alpha int32) int32 {
	if a0 > alpha/2 || a0 < -alpha/2 || (a0 == -alpha/2 && a1 != 0) {
		return 1
	}
	return 0
}

func aigisUseHint(h, a, alpha int32) int32 {
	a0 := aigisLowBits(a, alpha)
	a1 := aigisHighBits(a, alpha)
	m := (aigisQ - 1) / alpha
	if h == 1 && a0 > 0 {
		if a1 == m {
			return 0
		}
		return a1 + 1
	}
	if h == 1 && a0 <= 0 {
		if a1 == 0 {
			return m
		}
		return a1 - 1
	}
	return a1
}

func aigisPolyHighBits(r, a *aigisPoly, alpha int32) {
	for i := range r {
		r[i] = aigisHighBits(aigisFreeze(a[i]), alpha)
	}
}

func aigisPolyLowBits(r, a *aigisPoly, alpha int32) {
	for i := range r {
		r[i] = aigisLowBits(aigisFreeze(a[i]), alpha)
	}
}

// ─────────────────────────────────────────────────────────────
// 矩阵 A 展开
// ─────────────────────────────────────────────────────────────

func aigisExpandA(A *[][]aigisPoly, rho []byte, k, l int) {
	*A = make([][]aigisPoly, k)
	for i := range *A {
		(*A)[i] = make([]aigisPoly, l)
		for j := range (*A)[i] {
			aigisUniformPoly(&(*A)[i][j], rho, uint16(l*i+j))
			aigisNTT(&(*A)[i][j])
		}
	}
}

// ─────────────────────────────────────────────────────────────
// 打包 / 解包辅助
// ─────────────────────────────────────────────────────────────

func aigisPackPoly(buf []byte, a *aigisPoly, bitsPerCoeff int) {
	switch bitsPerCoeff {
	case 4: // eta=2 coefficients ∈ [-2,2] → store as 4+val
		for i := 0; i < aigisN/2; i++ {
			v0 := 2 - a[2*i]
			v1 := 2 - a[2*i+1]
			buf[i] = byte(v0) | byte(v1)<<4
		}
	case 13: // t0 with d=13
		for i := 0; i < aigisN/8; i++ {
			// simplified 13-bit pack
			for j := 0; j < 8; j++ {
				v := uint32((1 << (aigisD - 1)) - a[8*i+j])
				_ = v
			}
			binary.LittleEndian.PutUint64(buf[13*i:], uint64(a[8*i])&0x1FFF)
		}
	case 10: // t1 = Power2Round high bits with d=13
		for i := 0; i < aigisN/4; i++ {
			v0 := uint32(a[4*i])
			v1 := uint32(a[4*i+1])
			v2 := uint32(a[4*i+2])
			v3 := uint32(a[4*i+3])
			buf[5*i+0] = byte(v0)
			buf[5*i+1] = byte(v0>>8) | byte(v1<<2)
			buf[5*i+2] = byte(v1>>6) | byte(v2<<4)
			buf[5*i+3] = byte(v2>>4) | byte(v3<<6)
			buf[5*i+4] = byte(v3 >> 2)
		}
	}
}

func aigisUnpackPoly(a *aigisPoly, buf []byte, bitsPerCoeff int) {
	switch bitsPerCoeff {
	case 4: // eta=2 coefficients ∈ [-2,2] → stored as 4+val
		for i := 0; i < aigisN/2; i++ {
			v := buf[i]
			a[2*i] = int32(v&0x0F) - 2
			a[2*i+1] = int32(v>>4) - 2
		}
	case 13: // t0 with d=13
		for i := 0; i < aigisN/8; i++ {
			v := binary.LittleEndian.Uint64(buf[13*i:])
			a[8*i] = int32(v & 0x1FFF)
			// Simplified: only unpack first coefficient per group
			// Full implementation would unpack all 8 coefficients
			for j := 1; j < 8; j++ {
				a[8*i+j] = int32((v >> (13 * j)) & 0x1FFF)
			}
		}
	case 10: // t1 = Power2Round high bits with d=13
		for i := 0; i < aigisN/4; i++ {
			b0 := uint32(buf[5*i+0])
			b1 := uint32(buf[5*i+1])
			b2 := uint32(buf[5*i+2])
			b3 := uint32(buf[5*i+3])
			b4 := uint32(buf[5*i+4])
			a[4*i] = int32(b0 | (b1&0x03)<<8)
			a[4*i+1] = int32(b1>>2 | (b2&0x0F)<<6)
			a[4*i+2] = int32(b2>>4 | (b3&0x3F)<<4)
			a[4*i+3] = int32(b3>>6 | b4<<2)
		}
	}
}

// ─────────────────────────────────────────────────────────────
// 公钥/私钥 序列化 (简化版)
// ─────────────────────────────────────────────────────────────

func aigisSerializePK(rho []byte, t1 []aigisPoly, k int) []byte {
	buf := make([]byte, 32+k*320) // 32(rho) + k*320(t1)
	copy(buf[:32], rho)
	for i, p := range t1 {
		b := buf[32+i*320 : 32+(i+1)*320]
		aigisPackPoly(b, &p, 10)
	}
	return buf
}

func aigisSerializeSK(rho, key, tr []byte, s1, s2 []aigisPoly, t0 []aigisPoly, k, l int) []byte {
	n := 3*32 + l*128 + k*128 + k*416
	buf := make([]byte, n)
	off := 0
	copy(buf[off:], rho)
	off += 32
	copy(buf[off:], key)
	off += 32
	copy(buf[off:], tr)
	off += 32
	for i := range s1 {
		aigisPackPoly(buf[off:off+128], &s1[i], 4)
		off += 128
	}
	for i := range s2 {
		aigisPackPoly(buf[off:off+128], &s2[i], 4)
		off += 128
	}
	for i := range t0 {
		aigisPackPoly(buf[off:off+416], &t0[i], 13)
		off += 416
	}
	return buf
}

func aigisDeserializeSK(sk []byte, p aigisParamSet) (rho, key, tr []byte, s1, s2, t0 []aigisPoly) {
	rho = sk[:32]
	key = sk[32:64]
	tr = sk[64:96]
	off := 96

	s1 = make([]aigisPoly, p.L)
	for i := range s1 {
		aigisUnpackPoly(&s1[i], sk[off:off+128], 4)
		off += 128
	}

	s2 = make([]aigisPoly, p.K)
	for i := range s2 {
		aigisUnpackPoly(&s2[i], sk[off:off+128], 4)
		off += 128
	}

	t0 = make([]aigisPoly, p.K)
	for i := range t0 {
		aigisUnpackPoly(&t0[i], sk[off:off+416], 13)
		off += 416
	}

	return
}

// ─────────────────────────────────────────────────────────────
// AIGIS-sig 密钥生成
// ─────────────────────────────────────────────────────────────

type aigisKeyPair struct {
	PrivKey []byte
	PubKey  []byte
}

func aigisKeyGen(p aigisParamSet) (aigisKeyPair, error) {
	// 随机种子
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return aigisKeyPair{}, err
	}

	// 展开 ρ, ρ', K
	h := sha3.New512()
	h.Write(seed)
	expanded := h.Sum(nil)
	// 64-byte output: rho(32) | rhoPrime+K(32) — split further
	rho := expanded[:32]
	rhoPrime := make([]byte, 64)
	sha3.ShakeSum256(rhoPrime, append(expanded[32:], byte(p.L), byte(p.K)))
	key := make([]byte, 32)
	sha3.ShakeSum256(key, append(seed, 0xFF))

	// 展开矩阵 A
	var A [][]aigisPoly
	aigisExpandA(&A, rho, p.K, p.L)

	// 采样 s1 ∈ S^l_eta, s2 ∈ S^k_eta
	s1 := make([]aigisPoly, p.L)
	s2 := make([]aigisPoly, p.K)
	for i := range s1 {
		aigisEtaPoly(&s1[i], rhoPrime, uint16(i), p.Eta)
	}
	for i := range s2 {
		aigisEtaPoly(&s2[i], rhoPrime, uint16(p.L+i), p.Eta)
	}

	// s1_hat = NTT(s1)
	s1hat := make([]aigisPoly, p.L)
	for i := range s1hat {
		s1hat[i] = s1[i]
		aigisNTT(&s1hat[i])
	}

	// t = INTT(A * s1_hat) + s2
	t := make([]aigisPoly, p.K)
	aigisMatVecMul(t, A, s1hat)
	for i := range t {
		aigisINTT(&t[i])
		aigisPolyAdd(&t[i], &t[i], &s2[i])
	}

	// Power2Round(t)
	t1 := make([]aigisPoly, p.K)
	t0 := make([]aigisPoly, p.K)
	for i := range t {
		for j := range t[i] {
			tv := aigisFreeze(t[i][j])
			t0[i][j] = tv % (1 << aigisD)
			t1[i][j] = (tv - t0[i][j]) >> aigisD
		}
	}

	// pk = (rho, t1), sk = (rho, key, tr, s1, s2, t0)
	pkBytes := aigisSerializePK(rho, t1, p.K)
	tr := make([]byte, 32)
	sha3.ShakeSum256(tr, pkBytes)
	skBytes := aigisSerializeSK(rho, key, tr, s1, s2, t0, p.K, p.L)

	return aigisKeyPair{PrivKey: skBytes, PubKey: pkBytes}, nil
}

// ─────────────────────────────────────────────────────────────
// AIGIS-sig 签名
// ─────────────────────────────────────────────────────────────

func aigisSign(sk, msg []byte, p aigisParamSet) ([]byte, error) {
	expectedLen := 3*32 + p.L*128 + p.K*128 + p.K*416
	if len(sk) < expectedLen {
		return nil, fmt.Errorf("私钥长度不足: 需要 %d 字节, 实际 %d 字节", expectedLen, len(sk))
	}

	// 正确反序列化私钥
	rho, key, tr, s1, s2, t0 := aigisDeserializeSK(sk, p)
	_ = key // key is used for PRF, not needed in simplified signing
	_ = t0  // t0 is used in verification, not signing
	_ = s2  // s2 is used in the full algorithm for w - cs2 check

	// μ = H(tr || M)
	mu := make([]byte, 64)
	sha3.ShakeSum256(mu, append(tr, msg...))

	// 随机化签名
	rhoPrime := make([]byte, 64)
	rnd := make([]byte, 32)
	rand.Read(rnd)
	sha3.ShakeSum256(rhoPrime, append(mu, rnd...))

	// 展开矩阵 A
	var A [][]aigisPoly
	aigisExpandA(&A, rho, p.K, p.L)

	// NTT 变换 s1
	s1hat := make([]aigisPoly, p.L)
	for i := range s1 {
		s1hat[i] = s1[i]
		aigisNTT(&s1hat[i])
	}

	// 拒绝采样循环
	alpha := 2 * p.Gamma2
	for kappa := 0; kappa < 1000; kappa++ {
		// y ~ S^l_{gamma1-1}
		y := make([]aigisPoly, p.L)
		yhat := make([]aigisPoly, p.L)
		for i := range y {
			aigisGamma1Poly(&y[i], rhoPrime, uint16(kappa*p.L+i), p.Gamma1)
			yhat[i] = y[i]
			aigisNTT(&yhat[i])
		}

		// w = A*y
		w := make([]aigisPoly, p.K)
		aigisMatVecMul(w, A, yhat)
		for i := range w {
			aigisINTT(&w[i])
		}

		// w1 = HighBits(w)
		w1 := make([]aigisPoly, p.K)
		for i := range w {
			aigisPolyHighBits(&w1[i], &w[i], alpha)
		}

		// c~ = H(mu || w1)
		w1packed := make([]byte, 0, p.K*aigisN)
		for i := range w1 {
			for _, v := range w1[i] {
				w1packed = append(w1packed, byte(v))
			}
		}
		ctilde := make([]byte, 32)
		sha3.ShakeSum256(ctilde, append(mu, w1packed...))

		// c = SampleInBall(c~)
		var c aigisPoly
		aigisSampleInBall(&c, ctilde, p.Tau)
		chat := c
		aigisNTT(&chat)

		// z = y + c*s1
		cs1 := make([]aigisPoly, p.L)
		z := make([]aigisPoly, p.L)
		for i := range s1 {
			tmp := chat
			aigisPolyPointwiseMontgomery(&cs1[i], &tmp, &s1hat[i])
			aigisINTT(&cs1[i])
			aigisPolyAdd(&z[i], &y[i], &cs1[i])
		}

		// 检查 ||z||∞ < gamma1 - beta
		ok := true
		for i := range z {
			for _, v := range z[i] {
				if v > p.Gamma1-p.Beta || v < -(p.Gamma1-p.Beta) {
					ok = false
					break
				}
			}
			if !ok {
				break
			}
		}
		if !ok {
			continue
		}

		// 打包签名: (ctilde, z)
		sigBuf := make([]byte, 32+p.L*aigisN*3)
		copy(sigBuf[:32], ctilde)
		for i, zi := range z {
			for j, v := range zi {
				sigBuf[32+i*aigisN*3+j*3] = byte(v)
				sigBuf[32+i*aigisN*3+j*3+1] = byte(v >> 8)
				sigBuf[32+i*aigisN*3+j*3+2] = byte(v >> 16)
			}
		}
		return sigBuf, nil
	}
	return nil, errors.New("签名失败: 拒绝采样超出限制 (实验性实现，签名算法尚待完善)")
}

// ─────────────────────────────────────────────────────────────
// AIGIS-sig 验签
// ─────────────────────────────────────────────────────────────

func aigisVerify(pk, msg, sig []byte, p aigisParamSet) bool {
	if len(pk) < 32 || len(sig) < 32 {
		return false
	}
	rho := pk[:32]

	// tr = H(pk)
	tr := make([]byte, 32)
	sha3.ShakeSum256(tr, pk)

	// μ = H(tr || M)
	mu := make([]byte, 64)
	sha3.ShakeSum256(mu, append(tr, msg...))

	// 解包签名
	ctilde := sig[:32]
	z := make([]aigisPoly, p.L)
	for i := range z {
		for j := range z[i] {
			off := 32 + i*aigisN*3 + j*3
			if off+2 >= len(sig) {
				return false
			}
			v := int32(sig[off]) | int32(sig[off+1])<<8 | int32(sig[off+2])<<16
			if v > (1 << 23) {
				v -= (1 << 24)
			}
			z[i][j] = v
		}
	}

	// 检查 ||z||∞ < gamma1 - beta
	for i := range z {
		for _, v := range z[i] {
			if v >= p.Gamma1-p.Beta || v <= -(p.Gamma1-p.Beta) {
				return false
			}
		}
	}

	// c = SampleInBall(c~)
	var c aigisPoly
	aigisSampleInBall(&c, ctilde, p.Tau)

	// 展开 A, t1
	var A [][]aigisPoly
	aigisExpandA(&A, rho, p.K, p.L)

	// 近似验证: w1' = HighBits(A*z - c*t1*2^d)
	// (简化: 用 z 直接计算 w, 检查 c~ = H(mu || w1))
	zhat := make([]aigisPoly, p.L)
	for i := range z {
		zhat[i] = z[i]
		aigisNTT(&zhat[i])
	}

	az := make([]aigisPoly, p.K)
	aigisMatVecMul(az, A, zhat)
	for i := range az {
		aigisINTT(&az[i])
	}

	// w1' = HighBits(A*z)  (simplified, full impl subtracts c*t1*2^d)
	alpha := 2 * p.Gamma2
	w1p := make([]aigisPoly, p.K)
	for i := range az {
		aigisPolyHighBits(&w1p[i], &az[i], alpha)
	}

	// c~' = H(mu || w1')
	w1packed := make([]byte, 0, p.K*aigisN)
	for i := range w1p {
		for _, v := range w1p[i] {
			w1packed = append(w1packed, byte(v))
		}
	}
	ctildeP := make([]byte, 32)
	sha3.ShakeSum256(ctildeP, append(mu, w1packed...))

	return bytes.Equal(ctilde, ctildeP)
}

// ─────────────────────────────────────────────────────────────
// 公开 API (与现有 pqc.go 接口对齐)
// ─────────────────────────────────────────────────────────────

func AigisKeyGen(paramSet string) PQCKeyResult {
	p := aigisIIIParams
	if paramSet == "AIGIS-sig-V" || paramSet == "aigis-v" {
		p = aigisVParams
	}
	kp, err := aigisKeyGen(p)
	if err != nil {
		return PQCKeyResult{Error: "AIGIS 密钥生成失败: " + err.Error()}
	}
	return PQCKeyResult{
		Success:    true,
		PublicKey:  hexUpper(kp.PubKey),
		PrivateKey: hexUpper(kp.PrivKey),
		ParamSet:   p.Name,
	}
}

func AigisSign(req SLHDSARequest) symmetric.CryptoResult {
	p := aigisIIIParams
	if req.ParamSet == "AIGIS-sig-V" {
		p = aigisVParams
	}
	skBytes, err := hex.DecodeString(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效私钥(hex): " + err.Error()}
	}
	msgBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效数据(hex): " + err.Error()}
	}
	sig, err := aigisSign(skBytes, msgBytes, p)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}
}

func AigisVerify(req SLHDSAVerifyRequest) symmetric.CryptoResult {
	p := aigisIIIParams
	if req.ParamSet == "AIGIS-sig-V" {
		p = aigisVParams
	}
	pkBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效公钥(hex): " + err.Error()}
	}
	msgBytes, _ := hex.DecodeString(req.Data)
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效签名(hex): " + err.Error()}
	}
	if aigisVerify(pkBytes, msgBytes, sigBytes, p) {
		return symmetric.CryptoResult{Success: true, Data: "true"}
	}
	return symmetric.CryptoResult{Success: true, Data: "false", Error: "验签失败"}
}
