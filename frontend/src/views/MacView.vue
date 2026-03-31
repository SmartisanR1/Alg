<template>
  <PageLayout title="MAC 与 KDF" subtitle="CMAC · GMAC · Poly1305 · PBKDF2 · HKDF · bcrypt · scrypt · Argon2"
              icon-bg="bg-teal-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <ShieldHalfIcon class="w-4 h-4 text-teal-400" />
    </template>

    <!-- MAC -->
    <div v-if="activeTab === 'mac'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3 ck-right-panel">
        <div class="ck-card">
          <label class="ck-label">MAC算法</label>
          <select v-model="mac.algorithm" class="ck-select mb-3">
            <option value="CMAC-AES">CMAC-AES (RFC 4493)</option>
            <option value="GMAC">GMAC (AES-GCM)</option>
            <option value="Poly1305">Poly1305 (RFC 8439)</option>
            <option value="SipHash-2-4">SipHash-2-4</option>
          </select>
          <div>
            <div class="flex justify-between mb-1">
              <label class="ck-label !mb-0">密钥 (hex)</label>
              <button @click="genMacKey" class="text-xs text-violet-400">⚡ 生成</button>
            </div>
            <input v-model="mac.key" class="ck-input font-mono ck-trim-space" />
            <div v-if="macKeyHint" :class="['mt-1 text-xs', hintClass(macKeyHint)]">{{ macKeyHint }}</div>
            <div v-if="mac.key" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (mac.key.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div class="mt-2" v-if="mac.algorithm === 'GMAC'">
            <label class="ck-label">Nonce (hex, 12字节)</label>
            <input v-model="mac.iv" class="ck-input font-mono ck-trim-space" />
            <div v-if="macNonceHint" :class="['mt-1 text-xs', hintClass(macNonceHint)]">{{ macNonceHint }}</div>
          </div>
          <div class="mt-2">
            <CryptoPanel v-model="mac.data" label="数据 (hex)" type="textarea" :rows="3" clearable />
            <div v-if="macDataHint" :class="['mt-1 text-xs', hintClass(macDataHint)]">{{ macDataHint }}</div>
          </div>
          <button @click="computeMAC" class="ck-btn-primary w-full justify-center mt-2">
            <ShieldCheckIcon class="w-3.5 h-3.5" /> 计算 MAC
          </button>
        </div>
      </div>
      <div class="space-y-3 ck-right-panel">
        <div class="ck-card">
          <CryptoPanel v-model="macResult.data" label="MAC 结果" type="result" :success="macResult.success" copyable />
          <div v-if="macResult.error" class="mt-2 text-xs text-red-400">{{ macResult.error }}</div>
        </div>
        <div class="ck-card">
          <p class="ck-section-title">算法说明</p>
          <div class="text-xs space-y-2" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-2.5 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-violet-400 mb-1">{{ macPrinciple.title }}</p>
              <p v-for="(line, i) in macPrinciple.lines" :key="i">{{ line }}</p>
            </div>
            <div class="p-2.5 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-blue-400 mb-1">输入长度</p>
              <p>• 数据/密钥为 Hex 时长度需为偶数位</p>
              <p v-if="mac.algorithm === 'GMAC'">• Nonce 必须为 12 字节 (24位Hex)</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- KDF -->
    <div v-if="activeTab === 'kdf'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <div class="ck-card">
          <label class="ck-label">KDF算法</label>
          <select v-model="kdf.algorithm" class="ck-select mb-3">
            <option>PBKDF2-SHA1</option>
            <option>PBKDF2-SHA256</option>
            <option>PBKDF2-SHA512</option>
            <option>HKDF-SHA256</option>
            <option>HKDF-SHA512</option>
            <option>bcrypt</option>
            <option>scrypt</option>
            <option>Argon2i</option>
            <option>Argon2d</option>
            <option>Argon2id</option>
          </select>
          <div>
            <label class="ck-label">密码/输入密钥 (hex)</label>
            <input v-model="kdf.password" class="ck-input font-mono ck-trim-space mb-2" placeholder="密码的hex编码..." />
            <div v-if="kdfPasswordHint" :class="['mt-1 text-xs', hintClass(kdfPasswordHint)]">{{ kdfPasswordHint }}</div>
            <div v-if="kdf.password" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (kdf.password.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div v-if="!['bcrypt'].includes(kdf.algorithm)">
            <div class="flex justify-between mb-1">
              <label class="ck-label !mb-0">Salt (hex)</label>
              <button @click="genSalt" class="text-xs text-violet-400">⚡ 生成</button>
            </div>
            <input v-model="kdf.salt" class="ck-input font-mono ck-trim-space mb-2" placeholder="留空则自动生成..." />
            <div v-if="kdfSaltHint" :class="['mt-1 text-xs', hintClass(kdfSaltHint)]">{{ kdfSaltHint }}</div>
            <div v-if="kdf.salt" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (kdf.salt.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div v-if="['HKDF-SHA256','HKDF-SHA512'].includes(kdf.algorithm)">
            <label class="ck-label">Info (hex, 可选)</label>
            <input v-model="kdf.info" class="ck-input font-mono ck-trim-space mb-2" />
            <div v-if="kdfInfoHint" :class="['mt-1 text-xs', hintClass(kdfInfoHint)]">{{ kdfInfoHint }}</div>
            <div v-if="kdf.info" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (kdf.info.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div v-if="['PBKDF2-SHA1','PBKDF2-SHA256','PBKDF2-SHA512'].includes(kdf.algorithm)">
              <label class="ck-label">迭代次数</label>
              <input v-model.number="kdf.iterations" type="number" class="ck-input" placeholder="100000" />
            </div>
            <div v-if="kdf.algorithm === 'bcrypt'">
              <label class="ck-label">Cost (4-31)</label>
              <input v-model.number="kdf.cost" type="number" min="4" max="31" class="ck-input" placeholder="12" />
            </div>
            <div v-if="!['bcrypt'].includes(kdf.algorithm)">
              <label class="ck-label">输出长度(字节)</label>
              <input v-model.number="kdf.keyLen" type="number" class="ck-input" placeholder="32" />
            </div>
          </div>
          <!-- Argon2 params -->
          <div v-if="kdf.algorithm.startsWith('Argon2')" class="grid grid-cols-3 gap-2 mt-2">
            <div>
              <label class="ck-label">Time</label>
              <input v-model.number="kdf.time" type="number" class="ck-input" placeholder="3" />
            </div>
            <div>
              <label class="ck-label">Memory(KB)</label>
              <input v-model.number="kdf.memory" type="number" class="ck-input" placeholder="65536" />
            </div>
            <div>
              <label class="ck-label">Threads</label>
              <input v-model.number="kdf.threads" type="number" class="ck-input" placeholder="4" />
            </div>
          </div>
          <!-- scrypt params -->
          <div v-if="kdf.algorithm === 'scrypt'" class="grid grid-cols-3 gap-2 mt-2">
            <div>
              <label class="ck-label">N (CPU/Mem)</label>
              <input v-model.number="kdf.n" type="number" class="ck-input" placeholder="32768" />
            </div>
            <div>
              <label class="ck-label">r (Block)</label>
              <input v-model.number="kdf.r" type="number" class="ck-input" placeholder="8" />
            </div>
            <div>
              <label class="ck-label">p (Parallel)</label>
              <input v-model.number="kdf.p" type="number" class="ck-input" placeholder="1" />
            </div>
          </div>
          <button @click="deriveKey" class="ck-btn-primary w-full justify-center mt-3">
            <KeyIcon class="w-3.5 h-3.5" /> 派生密钥
          </button>
        </div>
      </div>
      <div class="space-y-3">
        <div class="ck-card">
          <CryptoPanel v-model="kdfResult.data" label="派生密钥" type="result" :success="kdfResult.success" copyable />
          <div v-if="kdfResult.extra" class="mt-2">
            <label class="ck-label text-amber-400">使用的Salt</label>
            <div class="ck-result !min-h-0 text-amber-300 text-xs">{{ kdfResult.extra }}</div>
          </div>
          <div v-if="kdfResult.error" class="mt-2 text-xs text-red-400">{{ kdfResult.error }}</div>
        </div>
        <div class="ck-card">
          <p class="ck-section-title">安全建议</p>
          <div class="text-xs space-y-1.5" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <p>🔐 <strong>密码存储</strong>: 推荐 Argon2id > bcrypt > scrypt</p>
            <p>🔑 <strong>密钥派生</strong>: 推荐 HKDF-SHA256 (RFC 5869)</p>
            <p>📁 <strong>加密密钥</strong>: PBKDF2-SHA256 (迭代≥100000)</p>
            <p>⚠️ Argon2id: time=3, mem=64MB, threads=4</p>
          </div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { storeToRefs } from 'pinia'
import { ShieldHalfIcon, ShieldCheckIcon, KeyIcon } from 'lucide-vue-next'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import { ComputeMAC, DeriveKey } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const { isDark } = storeToRefs(useAppStore())
const tabs = [{ id: 'mac', label: 'MAC' }, { id: 'kdf', label: 'KDF' }]
const activeTab = ref('mac')

const mac = reactive({ algorithm: 'CMAC-AES', key: '', iv: '', data: '' })
const macResult = reactive({ data: '', error: '', success: null })
const macKeyHint = computed(() => {
  const clean = (mac.key || '').replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) return '密钥 Hex 长度必须为偶数位'
  const byteLen = clean.length / 2
  if (mac.algorithm === 'Poly1305' && byteLen !== 32) {
    return 'Poly1305 密钥必须为 32 字节(64位Hex)'
  }
  if (mac.algorithm === 'SipHash-2-4' && byteLen !== 16) {
    return 'SipHash 推荐 16 字节(32位Hex) 密钥'
  }
  if ((mac.algorithm === 'CMAC-AES' || mac.algorithm === 'GMAC') && ![16, 24, 32].includes(byteLen)) {
    return 'AES 密钥长度应为 16/24/32 字节(32/48/64位Hex)'
  }
  return ''
})
const macNonceHint = computed(() => {
  if (mac.algorithm !== 'GMAC') return ''
  const clean = (mac.iv || '').replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'Nonce Hex 长度必须为偶数位'
  if (clean.length !== 24) return 'GMAC Nonce 必须为 12 字节(24位Hex)'
  return ''
})
const macDataHint = computed(() => {
  const clean = (mac.data || '').replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'Hex 长度必须为偶数位'
  return ''
})
const macPrinciple = computed(() => {
  switch (mac.algorithm) {
    case 'CMAC-AES':
      return {
        title: 'CMAC (NIST SP 800-38B)',
        lines: [
          '基于分组密码 (AES) 的消息认证码。',
          '采用 CBC-MAC + 子密钥处理最后一块，避免长度扩展问题。',
          '适合固定密钥下的完整性校验。'
        ]
      }
    case 'GMAC':
      return {
        title: 'GMAC (NIST SP 800-38D)',
        lines: [
          'GCM 的认证部分，等价于 GCM(空明文, AAD=data)。',
          '要求 (Key, Nonce) 组合全局唯一。',
          '提供完整性认证，不提供加密。'
        ]
      }
    case 'Poly1305':
      return {
        title: 'Poly1305 (RFC 8439)',
        lines: [
          '一次性消息认证码。',
          '必须保证密钥只使用一次，否则安全性降低。',
          '常与 ChaCha20 组合形成 AEAD。'
        ]
      }
    case 'SipHash-2-4':
      return {
        title: 'SipHash-2-4',
        lines: [
          '针对哈希表 DoS 的快速 MAC，适合短消息。',
          '2-4 表示 2 轮压缩 + 4 轮最终化。',
          '常用于哈希表键的消息认证。'
        ]
      }
    default:
      return { title: 'MAC', lines: [] }
  }
})

async function computeMAC() {
  const r = await ComputeMAC(mac)
  macResult.data = r.data; macResult.error = r.error; macResult.success = r.success
}
function genMacKey() {
  const len = mac.algorithm === 'Poly1305' ? 32 : 16
  const b = new Uint8Array(len); crypto.getRandomValues(b)
  mac.key = Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('').toUpperCase()
}

const kdf = reactive({
  algorithm: 'PBKDF2-SHA256', password: '', salt: '', info: '', keyLen: 32,
  iterations: 100000, cost: 12, time: 3, memory: 65536, threads: 4, n: 32768, r: 8, p: 1
})
const kdfResult = reactive({ data: '', error: '', extra: '', success: null })
const kdfPasswordHint = computed(() => {
  const clean = (kdf.password || '').replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) return '输入 Hex 长度必须为偶数位'
  return ''
})
const kdfSaltHint = computed(() => {
  if (['bcrypt'].includes(kdf.algorithm)) return ''
  const clean = (kdf.salt || '').replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'Salt Hex 长度必须为偶数位'
  return ''
})
const kdfInfoHint = computed(() => {
  if (!['HKDF-SHA256', 'HKDF-SHA512'].includes(kdf.algorithm)) return ''
  const clean = (kdf.info || '').replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'Info Hex 长度必须为偶数位'
  return ''
})

function hintClass(text) {
  if (!text) return ''
  if (text.includes('必须') || text.includes('需') || text.includes('应为')) return 'text-red-400'
  return 'text-amber-400'
}

async function deriveKey() {
  const r = await DeriveKey(kdf)
  kdfResult.data = r.data; kdfResult.error = r.error; kdfResult.extra = r.extra; kdfResult.success = r.success
}
function genSalt() {
  const b = new Uint8Array(16); crypto.getRandomValues(b)
  kdf.salt = Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('').toUpperCase()
}
</script>
