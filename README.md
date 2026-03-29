# CryptoKit — 全平台密码算法工具箱

> 基于 **Go + Wails v2 + Vue 3 + TailwindCSS** 构建的桌面密码工具，支持国密/国际/PQC算法全覆盖

---

## ✨ 功能特性

### 🌐 国际标准算法
- **对称加密**: AES-128/192/256 (ECB/CBC/CFB/OFB/CTR/GCM/CCM), DES/3DES, ChaCha20/XChaCha20, ChaCha20-Poly1305
- **非对称加密**: RSA-1024/2048/4096 (PKCS1/OAEP/PSS), ECDSA/ECDH (P-256/384/521)
- **现代椭圆曲线**: X25519, Ed25519, X448, Ed448
- **哈希**: MD5, SHA-1, SHA-2全系列, SHA-3全系列, SHAKE128/256, BLAKE2b/2s, BLAKE3, RIPEMD-160
- **HMAC**: HMAC-MD5/SHA1/SHA256/SHA512/SHA3/BLAKE2/SM3
- **MAC**: CMAC-AES, GMAC, Poly1305, SipHash-2-4
- **KDF**: PBKDF2, HKDF, bcrypt, scrypt, Argon2i/d/id

### 🇨🇳 国密算法 (GM/T 标准)
- **SM2**: 加解密、数字签名/验签、密钥协商 (GM/T 0003)
- **SM3**: 哈希、HMAC-SM3 (GM/T 0004)
- **SM4**: ECB/CBC/GCM 全模式 (GM/T 0006)
- **SM9**: 标识密码 (IBC): 加密、签名、密钥封装 (GM/T 0044)
- **ZUC**: 祖冲之流密码 ZUC-128/256 (GM/T 0001)

### 🔮 后量子密码 (NIST 标准)
- **ML-KEM** (Kyber): 512/768/1024 — FIPS 203
- **ML-DSA** (Dilithium): 44/65/87 — FIPS 204
- **SLH-DSA** (SPHINCS+): FIPS 205

### 🔧 工具箱
- Hex ↔ 字符串 ↔ Base64 (Standard/URL/NoPadding)
- URL编解码, Unicode转义
- XOR异或运算, 进制转换 (2/8/10/16)
- 随机密钥/IV/Nonce生成
- 数据填充 (PKCS7/PKCS5/Zero/ISO10126/ANSIX923)
- 时间戳转换 (Unix10/13, RFC3339, 日期时间)
- 文件哈希计算 (拖拽支持)
- 文件加解密 (AES-256-GCM)

---

## 🚀 构建步骤

### 1. 环境依赖

```bash
# 安装 Go 1.22+
https://go.dev/dl/

# 安装 Node.js 18+ (含 npm)
https://nodejs.org/

# 安装 Wails v2
go install github.com/wailsapp/wails/v2/cmd/wails@latest

# 验证环境
wails doctor
```

### 2. 克隆/解压项目

```bash
# 进入项目目录
cd cryptokit

# 下载 Go 依赖
go mod tidy

# 安装前端依赖
cd frontend && npm install && cd ..
```

### 3. 开发模式

```bash
wails dev
```

### 4. 生产构建

```bash
# 编译为原生应用
wails build

# 输出位置:
# Windows: build/bin/CryptoKit.exe
# macOS:   build/bin/CryptoKit.app
# Linux:   build/bin/CryptoKit
```

### 5. 跨平台编译

```bash
# 编译 Windows (在 Linux/macOS 上)
GOOS=windows GOARCH=amd64 wails build

# 编译 macOS ARM (M1/M2)
GOOS=darwin GOARCH=arm64 wails build

# 编译 Linux
GOOS=linux GOARCH=amd64 wails build
```

---

## 📁 项目结构

```
cryptokit/
├── main.go                  # Wails 入口
├── app.go                   # 所有后端 API 绑定
├── wails.json               # Wails 配置
├── go.mod / go.sum          # Go 模块
├── crypto/
│   ├── symmetric/           # AES / DES / ChaCha20
│   ├── asymmetric/          # RSA / ECC / Ed25519 / X25519
│   ├── hash/                # Hash + HMAC
│   ├── mac/                 # MAC (CMAC/GMAC/Poly1305)
│   ├── kdf/                 # PBKDF2 / HKDF / bcrypt / scrypt / Argon2
│   ├── gm/                  # SM2 / SM3 / SM4 / SM9 / ZUC
│   ├── pqc/                 # ML-KEM / ML-DSA / SLH-DSA
│   └── utils/               # 编解码工具
└── frontend/
    ├── src/
    │   ├── App.vue           # 主布局（侧边栏+路由+历史）
    │   ├── views/            # 各功能页面
    │   └── components/       # 公共组件
    └── package.json
```

---

## 🔑 核心依赖

| 依赖 | 用途 |
|------|------|
| `github.com/emmansun/gmsm` | SM2/SM3/SM4/SM9/ZUC 国密算法 |
| `github.com/cloudflare/circl` | ML-KEM/ML-DSA (PQC) |
| `golang.org/x/crypto` | ChaCha20/Ed25519/X25519/bcrypt/scrypt/Argon2 |
| `github.com/zeebo/blake3` | BLAKE3 哈希 |
| `github.com/wailsapp/wails/v2` | 跨平台桌面框架 |
| Vue 3 + TailwindCSS | 前端 UI |

---

⚠️ macOS 用户注意

由于 没有 Apple Developer 签名，从 Release 下载的 CryptoKit.app 可能会被 macOS 报告：

“无法验证开发者，可能包含恶意软件或泄露隐私”

解决办法（无需 Apple 账号）：

方式 1：右键打开
	1.	右键点击 CryptoKit.app → 选择 打开
	2.	弹窗选择 仍要打开
	3.	以后双击即可直接运行

方式 2：命令行解除隔离
在终端执行以下命令（假设下载在 ~/Downloads）：

    sudo xattr -r -d com.apple.quarantine ~/Downloads/CryptoKit.app
    
•	解除后可直接双击运行

•	仅需执行一次


## ⚠️ 安全说明

- 所有计算在本地进行，**数据不离开本机**
- **仅供学习/测试使用**，生产环境请参考正式密码工程规范
- ECB模式存在安全缺陷，不推荐在生产中使用
- RSA-1024 已不满足安全需求，建议使用 RSA-2048+

---

## 📜 License

MIT License
