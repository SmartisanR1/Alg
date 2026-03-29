<template>
  <PageLayout title="非对称加密 / 签名" subtitle="RSA · ECDSA · ECDH · Ed25519 · X25519 · Ed448 · X448"
              icon-bg="bg-cyan-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <KeyIcon class="w-4 h-4 text-cyan-400" />
    </template>

    <template #extra>
      <button @click="showPrinciple = true" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-violet-500/10 text-violet-400 hover:bg-violet-500/20 transition-all text-xs font-medium border border-violet-500/20">
        <InfoIcon class="w-3.5 h-3.5" /> 算法原理
      </button>
    </template>

    <!-- Principle Modal -->
    <transition name="fade">
      <div v-if="showPrinciple" class="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" @click.self="showPrinciple = false">
        <div class="ck-card max-w-lg w-full shadow-2xl animate-in zoom-in-95 duration-200" :class="isDark ? 'bg-dark-card border-dark-border' : 'bg-white border-gray-200'">
          <div class="flex justify-between items-center mb-4 border-b pb-3" :class="isDark ? 'border-dark-border' : 'border-gray-100'">
            <h3 class="text-sm font-bold flex items-center gap-2">
              <InfoIcon class="w-4 h-4 text-violet-400" /> {{ currentPrinciple.title }}
            </h3>
            <button @click="showPrinciple = false" class="p-1 hover:bg-gray-100 dark:hover:bg-dark-hover rounded-md transition-colors">
              <XIcon class="w-4 h-4 text-dark-muted" />
            </button>
          </div>
          <div class="text-xs leading-relaxed space-y-3" :class="isDark ? 'text-dark-muted' : 'text-gray-600'">
            <p>{{ currentPrinciple.content }}</p>
          </div>
          <div class="mt-6 flex justify-end">
            <button @click="showPrinciple = false" class="ck-btn-primary px-6">确定</button>
          </div>
        </div>
      </div>
    </transition>

    <!-- RSA -->
    <div v-if="activeTab === 'rsa'" class="grid grid-cols-2 gap-4 animate-fade-in h-full overflow-hidden">
      <div class="space-y-3 overflow-y-auto pr-1">
        <div class="ck-card">
          <p class="ck-section-title">RSA 密钥生成</p>
          <div class="flex gap-2 mb-4">
            <select v-model="rsa.bits" class="ck-select flex-1">
              <option :value="1024">1024 bit</option>
              <option :value="2048">2048 bit</option>
              <option :value="3072">3072 bit</option>
              <option :value="4096">4096 bit</option>
            </select>
            <select v-model="asymKeyFormat" class="ck-select flex-1">
              <option value="pem">PEM 格式</option>
              <option value="hex">HEX 格式</option>
            </select>
            <button @click="genRSAKey" class="ck-btn-primary flex-1 justify-center">
              <KeyIcon class="w-3.5 h-3.5" /> 生成密钥
            </button>
          </div>
          <div v-if="rsaKeys.privateKey" class="space-y-3 animate-in fade-in duration-300">
            <div>
              <div class="flex justify-between mb-1">
                <label class="ck-label !mb-0 text-amber-400">私钥 ({{ asymKeyFormat.toUpperCase() }})</label>
                <button @click="copy(asymKeyFormat === 'pem' ? rsaKeys.privateKey : rsaKeys.privHex)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="ck-result ck-key-hex !min-h-0 text-amber-300 !text-[10px] break-all max-h-32 overflow-y-auto font-mono">
                {{ asymKeyFormat === 'pem' ? rsaKeys.privateKey : rsaKeys.privHex }}
              </div>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                  私钥 {{ asymKeyFormat === 'hex' ? (rsaKeys.privHex.length / 2) + ' bytes' : (rsaKeys.privateKey.split('\n').length + ' lines') }}
                </span>
              </div>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="ck-label !mb-0 text-cyan-400">公钥 ({{ asymKeyFormat.toUpperCase() }})</label>
                <button @click="copy(asymKeyFormat === 'pem' ? rsaKeys.publicKey : rsaKeys.pubHex)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="ck-result ck-key-hex !min-h-0 text-cyan-300 !text-[10px] break-all max-h-24 overflow-y-auto font-mono">
                {{ asymKeyFormat === 'pem' ? rsaKeys.publicKey : rsaKeys.pubHex }}
              </div>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-cyan-400 border-cyan-500/20 bg-cyan-500/5">
                  公钥 {{ asymKeyFormat === 'hex' ? (rsaKeys.pubHex.length / 2) + ' bytes' : (rsaKeys.publicKey.split('\n').length + ' lines') }}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div class="ck-card space-y-2">
          <div class="grid grid-cols-2 gap-3 mb-2">
            <div>
              <label class="ck-label">填充模式 (Padding)</label>
              <select v-model="rsa.padding" class="ck-select">
                <option value="PKCS1v15">PKCS#1 v1.5</option>
                <option value="OAEP">OAEP (加密推荐)</option>
                <option value="PSS">PSS (签名推荐)</option>
              </select>
            </div>
            <div>
              <label class="ck-label">Hash 算法</label>
              <select v-model="rsa.hash" class="ck-select">
                <option value="SHA256">SHA-256</option>
                <option value="SHA384">SHA-384</option>
                <option value="SHA512">SHA-512</option>
                <option value="SHA1">SHA-1 (旧标准)</option>
              </select>
            </div>
          </div>
          <div>
            <label class="ck-label">密钥内容 (PEM/Hex)</label>
            <textarea v-model="rsa.key" class="ck-textarea text-[10px] font-mono" rows="4" placeholder="粘贴公钥(加密/验签)或私钥(解密/签名)..." />
          </div>
          <CryptoPanel v-model="rsa.data" label="待处理数据 (Hex)" type="textarea" :rows="3" clearable />
        </div>
      </div>
      <div class="space-y-3 flex flex-col min-h-0 overflow-hidden ck-right-panel">
        <div class="grid grid-cols-2 gap-2 shrink-0">
          <button @click="rsaEncrypt" class="ck-btn-primary justify-center"><LockIcon class="w-3.5 h-3.5"/>加密</button>
          <button @click="rsaDecrypt" class="ck-btn-secondary justify-center"><UnlockIcon class="w-3.5 h-3.5"/>解密</button>
          <button @click="rsaSign" class="ck-btn-success justify-center"><PenIcon class="w-3.5 h-3.5"/>签名</button>
          <button @click="rsaVerify" class="ck-btn-secondary justify-center"><CheckCircleIcon class="w-3.5 h-3.5"/>验签</button>
        </div>
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="rsaResult.data" label="运算结果" type="result" :success="rsaResult.success" copyable />
          <div v-if="rsaResult.error" class="mt-2 text-xs text-red-400">{{ rsaResult.error }}</div>
        </div>
        <div class="ck-card flex-1 overflow-y-auto">
          <p class="ck-section-title">算法原理 (RSA)</p>
          <div class="text-[11px] space-y-3 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-3 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-violet-400">数学基础</p>
              <p>• 安全性基于大整数因子分解难题 (Factoring Problem)。</p>
              <p>• 选取两个大素数 p 和 q，计算 n = pq，φ(n) = (p-1)(q-1)。</p>
            </div>
            <div class="p-3 rounded-lg border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-emerald-400">填充模式说明</p>
              <p>1. <span class="text-emerald-500">OAEP</span>: 现代加密标准，通过掩码函数增强随机性，防止选择密文攻击。</p>
              <p>2. <span class="text-emerald-500">PSS</span>: 现代签名标准，概率性签名方案，具有更强的安全性证明。</p>
              <p>3. <span class="text-emerald-500">PKCS#1 v1.5</span>: 较旧的标准，虽广泛使用但已知存在某些弱点。</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ECC -->
    <div v-if="activeTab === 'ecc'" class="grid grid-cols-2 gap-4 animate-fade-in h-full overflow-hidden">
      <div class="space-y-3 overflow-y-auto pr-1">
        <div class="ck-card">
          <p class="ck-section-title">ECC 曲线密钥生成</p>
          <div class="flex gap-2 mb-4">
            <select v-model="ecc.curve" class="ck-select flex-1">
              <option value="P-256">NIST P-256 (prime256v1)</option>
              <option value="P-384">NIST P-384 (secp384r1)</option>
              <option value="P-521">NIST P-521 (secp521r1)</option>
              <option value="SM2">国密 SM2 (sm2p256v1)</option>
              <option value="secp256k1">Bitcoin (secp256k1)</option>
            </select>
            <button @click="genECCKey" class="ck-btn-primary flex-1 justify-center">
              <KeyIcon class="w-3.5 h-3.5" /> 生成密钥
            </button>
          </div>
          <div v-if="eccKeys.privateKey" class="space-y-3 animate-in fade-in duration-300">
            <div>
              <div class="flex justify-between mb-1">
                <label class="ck-label !mb-0 text-amber-400">私钥 (PEM/Hex)</label>
                <button @click="copy(asymKeyFormat === 'pem' ? eccKeys.privateKey : eccKeys.privHex)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="ck-result ck-key-hex !min-h-0 text-amber-300 !text-[10px] break-all max-h-32 overflow-y-auto font-mono">
                {{ asymKeyFormat === 'pem' ? eccKeys.privateKey : eccKeys.privHex }}
              </div>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                  私钥 {{ asymKeyFormat === 'hex' ? (eccKeys.privHex.length / 2) + ' bytes' : (eccKeys.privateKey.split('\n').length + ' lines') }}
                </span>
              </div>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="ck-label !mb-0 text-cyan-400">公钥 (PEM/Hex)</label>
                <button @click="copy(asymKeyFormat === 'pem' ? eccKeys.publicKey : eccKeys.pubHex)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="ck-result ck-key-hex !min-h-0 text-cyan-300 !text-[10px] break-all max-h-24 overflow-y-auto font-mono">
                {{ asymKeyFormat === 'pem' ? eccKeys.publicKey : eccKeys.pubHex }}
              </div>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-cyan-400 border-cyan-500/20 bg-cyan-500/5">
                  公钥 {{ asymKeyFormat === 'hex' ? (eccKeys.pubHex.length / 2) + ' bytes' : (eccKeys.publicKey.split('\n').length + ' lines') }}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div class="ck-card space-y-2">
          <div>
            <label class="ck-label">密钥内容 (PEM/Hex)</label>
            <textarea v-model="ecc.key" class="ck-textarea text-[10px] font-mono" rows="4" placeholder="粘贴私钥(签名)或公钥(验签/ECDH)..." />
          </div>
          <div>
            <label class="ck-label">对方公钥 (仅 ECDH 使用)</label>
            <textarea v-model="ecc.peerKey" class="ck-textarea text-[10px] font-mono" rows="2" placeholder="密钥交换时填入对方公钥..." />
          </div>
          <CryptoPanel v-model="ecc.data" label="待处理数据 (Hex)" type="input" clearable />
        </div>
      </div>
      <div class="space-y-3 flex flex-col min-h-0 overflow-hidden ck-right-panel">
        <div class="grid grid-cols-3 gap-2 shrink-0">
          <button @click="eccSign" class="ck-btn-primary justify-center text-xs"><PenIcon class="w-3.5 h-3.5"/>签名</button>
          <button @click="eccVerify" class="ck-btn-secondary justify-center text-xs"><CheckCircleIcon class="w-3.5 h-3.5"/>验签</button>
          <button @click="ecdhCompute" class="ck-btn-success justify-center text-xs"><LinkIcon class="w-3.5 h-3.5"/>ECDH</button>
        </div>
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="eccResult.data" label="运算结果" type="result" :success="eccResult.success" copyable />
          <div v-if="eccResult.error" class="mt-2 text-xs text-red-400">{{ eccResult.error }}</div>
        </div>
        <div class="ck-card flex-1 overflow-y-auto">
          <p class="ck-section-title">算法原理 (ECC)</p>
          <div class="text-[11px] space-y-3 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-3 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-violet-400">数学基础</p>
              <p>• 安全性基于椭圆曲线离散对数难题 (ECDLP)。</p>
              <p>• 优势：在同等安全强度下，密钥长度远小于 RSA (如 256位 ECC 约等于 3072位 RSA)。</p>
            </div>
            <div class="p-3 rounded-lg border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-emerald-400">核心应用</p>
              <p>1. <span class="text-emerald-500">ECDSA</span>: 椭圆曲线数字签名算法。</p>
              <p>2. <span class="text-emerald-500">ECDH</span>: 椭圆曲线 Diffie-Hellman 密钥交换。</p>
              <p>3. <span class="text-emerald-500">ECIES</span>: 椭圆曲线集成加密方案。</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Ed25519 / X25519 -->
    <div v-if="activeTab === 'curve25519'" class="grid grid-cols-2 gap-4 animate-fade-in h-full overflow-hidden">
      <div class="space-y-3 overflow-y-auto pr-1">
        <div class="ck-card">
          <p class="ck-section-title">Curve25519 系列操作</p>
          <div class="flex gap-2 mb-3">
            <button @click="genX25519" class="ck-btn-primary flex-1 text-xs justify-center">
              <KeyIcon class="w-3 h-3" /> X25519 密钥对
            </button>
            <button @click="genEd25519" class="ck-btn-secondary flex-1 text-xs justify-center">
              <KeyIcon class="w-3 h-3" /> Ed25519 密钥对
            </button>
            <button @click="genEd448" class="ck-btn-secondary flex-1 text-xs justify-center">
              <KeyIcon class="w-3 h-3" /> Ed448 密钥对
            </button>
          </div>
          <div v-if="c25519.privateKey" class="space-y-2 animate-in fade-in duration-300">
            <div>
              <label class="ck-label text-amber-400">私钥 (Hex)</label>
              <div class="ck-result ck-key-hex !min-h-0 text-amber-300 text-[10px] font-mono break-all">{{ c25519.privateKey }}</div>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                  私钥 {{ (c25519.privateKey.length / 2) + ' bytes' }}
                </span>
              </div>
            </div>
            <div>
              <label class="ck-label text-cyan-400">公钥 (Hex)</label>
              <div class="ck-result ck-key-hex !min-h-0 text-cyan-300 text-[10px] font-mono break-all">{{ c25519.publicKey }}</div>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-cyan-400 border-cyan-500/20 bg-cyan-500/5">
                  公钥 {{ (c25519.publicKey.length / 2) + ' bytes' }}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div class="ck-card space-y-2">
          <p class="ck-section-title">Ed448 签名/验签</p>
          <div>
            <label class="ck-label">私钥 (Hex)</label>
            <input v-model="ed448.privateKey" class="ck-input font-mono ck-trim-space text-[10px]" />
          </div>
          <div>
            <label class="ck-label">公钥 (Hex)</label>
            <input v-model="ed448.publicKey" class="ck-input font-mono ck-trim-space text-[10px]" />
          </div>
          <div>
            <label class="ck-label">Context (可选)</label>
            <input v-model="ed448.context" class="ck-input text-xs" />
          </div>
          <CryptoPanel v-model="ed448.data" label="待处理数据 (Hex)" type="input" clearable />
          <CryptoPanel v-model="ed448.signature" label="签名 (Hex)" type="input" clearable />
          <div class="grid grid-cols-2 gap-2">
            <button @click="ed448Sign" class="ck-btn-success text-xs justify-center"><PenIcon class="w-3.5 h-3.5"/>Ed448 签名</button>
            <button @click="ed448Verify" class="ck-btn-secondary text-xs justify-center"><CheckCircleIcon class="w-3.5 h-3.5"/>Ed448 验签</button>
          </div>
        </div>
        <div class="ck-card space-y-2">
          <div>
            <label class="ck-label">私钥 (Hex)</label>
            <input v-model="c25519.usePriv" class="ck-input font-mono ck-trim-space text-[10px]" />
          </div>
          <div>
            <label class="ck-label">对方公钥 / 待验证签名 (Hex)</label>
            <input v-model="c25519.peerPub" class="ck-input font-mono ck-trim-space text-[10px]" />
          </div>
          <CryptoPanel v-model="c25519.data" label="待处理数据 (Hex)" type="input" clearable />
        </div>
      </div>
      <div class="space-y-3 flex flex-col min-h-0 overflow-hidden ck-right-panel">
        <div class="grid grid-cols-2 gap-2 shrink-0">
          <button @click="x25519Exchange" class="ck-btn-primary text-xs justify-center"><LinkIcon class="w-3.5 h-3.5"/>X25519 密钥交换</button>
          <button @click="ed25519Sign" class="ck-btn-success text-xs justify-center"><PenIcon class="w-3.5 h-3.5"/>Ed25519 签名</button>
          <button @click="ed25519Verify" class="ck-btn-secondary col-span-2 text-xs justify-center"><CheckCircleIcon class="w-3.5 h-3.5"/>Ed25519 验签</button>
        </div>
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="c25519Result.data" label="运算结果" type="result" :success="c25519Result.success" copyable />
          <div v-if="c25519Result.error" class="mt-2 text-xs text-red-400">{{ c25519Result.error }}</div>
        </div>
        <div class="ck-card flex-1 overflow-y-auto">
          <p class="ck-section-title">算法原理 (Curve25519)</p>
          <div class="text-[11px] space-y-3 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-3 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-violet-400">设计理念</p>
              <p>• 由 Daniel J. Bernstein 设计，目标是提供极高性能且抗侧信道攻击。</p>
              <p>• 采用蒙哥马利曲线 (Montgomery Curve)，计算过程不包含条件分支。</p>
            </div>
            <div class="p-3 rounded-lg border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-emerald-400">组件说明</p>
              <p>1. <span class="text-emerald-500">X25519</span>: 专门优化的 Diffie-Hellman 密钥交换协议 (RFC 7748)。</p>
              <p>2. <span class="text-emerald-500">Ed25519</span>: 基于 Edwards 曲线的数字签名算法 (RFC 8032)，速度极快。</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { KeyIcon, LockIcon, UnlockIcon, PenIcon, CheckCircleIcon, CopyIcon, LinkIcon, InfoIcon, XIcon } from 'lucide-vue-next'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import { RSAGenerateKey, RSAEncrypt, RSADecrypt, RSASign, RSAVerify, ECCGenerateKey, ECCSign, ECCVerify, ECDHCompute, X25519KeyGen, X25519Exchange, Ed25519KeyGen, Ed25519Sign, Ed25519Verify, Ed448KeyGen, Ed448Sign, Ed448Verify } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'rsa', label: 'RSA' },
  { id: 'ecc', label: 'ECC (ECDSA/ECDH)' },
  { id: 'curve25519', label: 'Ed25519 / X25519' },
]
const activeTab = ref('rsa')

// Principles modal / info
const showPrinciple = ref(false)
const principles = {
  rsa: {
    title: 'RSA 算法原理',
    content: 'RSA 是最早的非对称加密算法之一，安全性基于大整数分解难题。加密和签名时可选择不同的填充模式：\n1. PKCS#1 v1.5: 传统模式，简单但对某些攻击较脆弱。\n2. OAEP (Optimal Asymmetric Encryption Padding): 推荐用于加密，引入随机性提高安全性。\n3. PSS (Probabilistic Signature Scheme): 推荐用于签名，安全性证明更强。'
  },
  ecc: {
    title: 'ECC 椭圆曲线原理',
    content: 'ECC (Elliptic Curve Cryptography) 安全性基于椭圆曲线离散对数难题。相比 RSA，ECC 在相同安全级别下密钥更短，计算更快。广泛用于 ECDSA 签名和 ECDH 密钥交换。支持 NIST 曲线、国密 SM2 和 Bitcoin 的 secp256k1。'
  },
  curve25519: {
    title: 'Curve25519 原理',
    content: '由 Daniel J. Bernstein 设计，旨在提供极高性能且不牺牲安全性。X25519 用于 Diffie-Hellman 密钥交换，Ed25519 用于数字签名。它们的设计避免了传统 ECC 曲线中的许多潜在陷阱（如侧信道攻击）。'
  }
}

const currentPrinciple = computed(() => principles[activeTab.value])

const asymKeyFormat = ref('hex')
const byteCount = (s) => s ? (s.length / 2).toFixed(0) : 0

// RSA
const rsa = reactive({ bits: 2048, padding: 'OAEP', hash: 'SHA256', key: '', data: '', sigData: '' })
const rsaKeys = reactive({ privateKey: '', publicKey: '', privHex: '', pubHex: '' })
const rsaResult = reactive({ data: '', error: '', success: null })

async function genRSAKey() {
  const r = await RSAGenerateKey(rsa.bits)
  if (r.success) { 
    rsaKeys.privateKey = r.privateKey; rsaKeys.publicKey = r.publicKey 
    rsaKeys.privHex = r.privHex; rsaKeys.pubHex = r.pubHex
    
    // Auto sync
    rsa.key = asymKeyFormat.value === 'pem' ? r.publicKey : r.pubHex
  }
}
async function rsaEncrypt() {
  const r = await RSAEncrypt({ key: rsa.key, data: rsa.data, padding: rsa.padding, hash: rsa.hash })
  rsaResult.data = r.data; rsaResult.error = r.error; rsaResult.success = r.success
}
async function rsaDecrypt() {
  const r = await RSADecrypt({ key: rsa.key, data: rsa.data, padding: rsa.padding, hash: rsa.hash })
  rsaResult.data = r.data; rsaResult.error = r.error; rsaResult.success = r.success
}
async function rsaSign() {
  const r = await RSASign({ privateKey: rsa.key, data: rsa.data, hash: rsa.hash, padding: rsa.padding === 'PSS' ? 'PSS' : 'PKCS1v15' })
  rsaResult.data = r.data; rsaResult.error = r.error; rsaResult.success = r.success
}
async function rsaVerify() {
  const r = await RSAVerify({ publicKey: rsa.key, data: rsa.data, signature: rsaResult.data, hash: rsa.hash, padding: rsa.padding === 'PSS' ? 'PSS' : 'PKCS1v15' })
  rsaResult.data = r.data; rsaResult.error = r.error; rsaResult.success = r.success
}

// ECC
const ecc = reactive({ curve: 'P-256', hash: 'SHA256', key: '', peerKey: '', data: '' })
const eccKeys = reactive({ privateKey: '', publicKey: '', privHex: '', pubHex: '' })
const eccResult = reactive({ data: '', error: '', success: null })

async function genECCKey() {
  const r = await ECCGenerateKey(ecc.curve)
  if (r.success) { 
    eccKeys.privateKey = r.privateKey; eccKeys.publicKey = r.publicKey 
    eccKeys.privHex = r.privHex; eccKeys.pubHex = r.pubHex

    // Auto sync
    ecc.key = asymKeyFormat.value === 'pem' ? r.publicKey : r.pubHex
  }
}

// Watchers for format sync
watch(asymKeyFormat, (newFormat) => {
  if (rsaKeys.publicKey) {
    rsa.key = newFormat === 'pem' ? rsaKeys.publicKey : rsaKeys.pubHex
  }
  if (eccKeys.publicKey) {
    ecc.key = newFormat === 'pem' ? eccKeys.publicKey : eccKeys.pubHex
  }
})

async function eccSign() {
  const r = await ECCSign({ privateKey: ecc.key, data: ecc.data, hash: ecc.hash, curve: ecc.curve })
  eccResult.data = r.data; eccResult.error = r.error; eccResult.success = r.success
}
async function eccVerify() {
  const r = await ECCVerify({ publicKey: ecc.key, data: ecc.data, signature: eccResult.data, hash: ecc.hash, curve: ecc.curve })
  eccResult.data = r.data; eccResult.error = r.error; eccResult.success = r.success
}
async function ecdhCompute() {
  const r = await ECDHCompute({ privateKey: ecc.key, peerPublicKey: ecc.peerKey, curve: ecc.curve })
  eccResult.data = r.data; eccResult.error = r.error; eccResult.success = r.success
}

// Curve25519 / Ed448
const c25519 = reactive({ privateKey: '', publicKey: '', usePriv: '', peerPub: '', data: '' })
const c25519Result = reactive({ data: '', error: '', success: null })
const ed448 = reactive({ privateKey: '', publicKey: '', data: '', signature: '', context: '' })

async function genX25519() {
  const r = await X25519KeyGen()
  if (r.success) { c25519.privateKey = r.privateKey; c25519.publicKey = r.publicKey; c25519.usePriv = r.privateKey }
}
async function genEd25519() {
  const r = await Ed25519KeyGen()
  if (r.success) { c25519.privateKey = r.privateKey; c25519.publicKey = r.publicKey; c25519.usePriv = r.privateKey }
}
async function genEd448() {
  const r = await Ed448KeyGen()
  if (r.success) { ed448.privateKey = r.privateKey; ed448.publicKey = r.publicKey }
}
async function x25519Exchange() {
  const r = await X25519Exchange({ privateKey: c25519.usePriv, peerPublicKey: c25519.peerPub })
  c25519Result.data = r.data; c25519Result.error = r.error; c25519Result.success = r.success
}
async function ed25519Sign() {
  const r = await Ed25519Sign({ privateKey: c25519.usePriv, data: c25519.data })
  c25519Result.data = r.data; c25519Result.error = r.error; c25519Result.success = r.success
}
async function ed25519Verify() {
  const r = await Ed25519Verify({ publicKey: c25519.publicKey, data: c25519.data, signature: c25519Result.data })
  c25519Result.data = r.data; c25519Result.error = r.error; c25519Result.success = r.success
}
async function ed448Sign() {
  const r = await Ed448Sign({ privateKey: ed448.privateKey, data: ed448.data, context: ed448.context })
  if (r.data) ed448.signature = r.data
  c25519Result.data = r.data; c25519Result.error = r.error; c25519Result.success = r.success
}
async function ed448Verify() {
  const r = await Ed448Verify({ publicKey: ed448.publicKey, data: ed448.data, signature: ed448.signature, context: ed448.context })
  c25519Result.data = r.data; c25519Result.error = r.error; c25519Result.success = r.success
}

async function copy(t) {
  if (!t) return
  await navigator.clipboard.writeText(t)
  store.showToast('已复制')
}
</script>
