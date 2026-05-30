<template>
  <PageLayout title="MAC 与 KDF" subtitle="CMAC · GMAC · Poly1305 · PBKDF2 · HKDF · bcrypt · scrypt · Argon2"
              icon-bg="bg-teal-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <ShieldHalfIcon class="w-4 h-4 text-teal-400" />
    </template>

    <template #actions>
      <Button variant="secondary" size="sm" @click="showPrinciple = true">
        <InfoIcon class="w-3.5 h-3.5" /> 算法原理
      </Button>
    </template>

    <!-- Principle Modal -->
    <transition name="fade">
      <div v-if="showPrinciple" class="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" @click.self="showPrinciple = false">
        <div class="card max-w-2xl w-full shadow-2xl animate-in zoom-in-95 duration-200 overflow-hidden flex flex-col max-h-[85vh]">
          <div class="flex justify-between items-center p-4 border-b shrink-0">
            <h3 class="text-sm font-bold flex items-center gap-2">
              <ShieldCheckIcon class="w-4 h-4 text-violet-400" /> {{ currentPrinciple.title }}
            </h3>
            <button @click="showPrinciple = false" class="p-1 hover:bg-gray-100 dark:hover:bg-dark-hover rounded-md transition-colors">
              <XIcon class="w-4 h-4 text-dark-muted" />
            </button>
          </div>
          <div class="flex-1 overflow-y-auto p-6 custom-scrollbar">
            <AlgorithmPrinciple
              :title="currentPrinciple.title"
              type="mac"
              :sections="parsedPrinciples"
            />
          </div>
          <div class="p-4 border-t shrink-0 flex justify-end bg-gray-50/50 dark:bg-dark-bg/20">
            <Button variant="primary" @click="showPrinciple = false">确认并返回</Button>
          </div>
        </div>
      </div>
    </transition>

    <!-- MAC -->
    <div v-if="activeTab === 'mac'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3 sym-main">
        <Card title="MAC 算法">
          <label class="input-label">MAC算法</label>
          <Dropdown
            v-model="mac.algorithm"
            :options="[
              { value: 'CMAC-AES', label: 'CMAC-AES (RFC 4493)' },
              { value: 'GMAC', label: 'GMAC (AES-GCM)' },
              { value: 'Poly1305', label: 'Poly1305 (RFC 8439)' },
              { value: 'SipHash-2-4', label: 'SipHash-2-4' }
            ]"
            class="mb-3"
          />
          <div>
            <div class="flex justify-between mb-1">
              <label class="input-label !mb-0">密钥 (hex)</label>
              <Button variant="tool" size="sm" @click="genMacKey">⚡ 生成</Button>
            </div>
            <Input v-model="mac.key" class="font-mono" />
            <div v-if="macKeyHint" :class="['mt-1 text-xs', hintClass(macKeyHint)]">{{ macKeyHint }}</div>
            <div v-if="mac.key" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-200 border-amber-400/30 bg-amber-400/10">
                {{ (mac.key.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div class="mt-2" v-if="mac.algorithm === 'GMAC'">
            <Input v-model="mac.iv" label="Nonce (hex, 12字节)" class="font-mono" />
            <div v-if="macNonceHint" :class="['mt-1 text-xs', hintClass(macNonceHint)]">{{ macNonceHint }}</div>
          </div>
          <div class="mt-2">
            <CryptoPanel v-model="mac.data" label="数据 (hex)" type="textarea" :rows="3" clearable />
            <div v-if="macDataHint" :class="['mt-1 text-xs', hintClass(macDataHint)]">{{ macDataHint }}</div>
          </div>
          <Button variant="success" block @click="computeMAC" class="mt-2">
            <ShieldCheckIcon class="w-3.5 h-3.5" /> 计算 MAC
          </Button>
        </Card>
      </div>
      <div class="space-y-3 sym-main">
        <Card title="MAC 结果">
          <ResultArea
            :modelValue="macResult.data"
            :error="macResult.error"
            :success="macResult.success"
            label="MAC 结果"
            copyable
          />
        </Card>
        <Card title="算法说明">
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
        </Card>
      </div>
    </div>

    <!-- KDF -->
    <div v-if="activeTab === 'kdf'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <Card title="KDF 算法">
          <label class="input-label">KDF算法</label>
          <Dropdown
            v-model="kdf.algorithm"
            :options="[
              { value: 'PBKDF2-SHA1', label: 'PBKDF2-SHA1' },
              { value: 'PBKDF2-SHA256', label: 'PBKDF2-SHA256' },
              { value: 'PBKDF2-SHA512', label: 'PBKDF2-SHA512' },
              { value: 'HKDF-SHA256', label: 'HKDF-SHA256' },
              { value: 'HKDF-SHA512', label: 'HKDF-SHA512' },
              { value: 'bcrypt', label: 'bcrypt' },
              { value: 'scrypt', label: 'scrypt' },
              { value: 'Argon2i', label: 'Argon2i' },
              { value: 'Argon2d', label: 'Argon2d' },
              { value: 'Argon2id', label: 'Argon2id' }
            ]"
            class="mb-3"
          />
          <div>
            <Input v-model="kdf.password" label="密码/输入密钥 (hex)" class="font-mono ck-trim-space mb-2" placeholder="密码的hex编码..." />
            <div v-if="kdfPasswordHint" :class="['mt-1 text-xs', hintClass(kdfPasswordHint)]">{{ kdfPasswordHint }}</div>
            <div v-if="kdf.password" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-200 border-amber-400/30 bg-amber-400/10">
                {{ (kdf.password.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div v-if="!['bcrypt'].includes(kdf.algorithm)">
            <div class="flex justify-between mb-1">
              <label class="input-label !mb-0">Salt (hex)</label>
              <Button variant="tool" size="sm" @click="genSalt">⚡ 生成</Button>
            </div>
            <Input v-model="kdf.salt" class="font-mono ck-trim-space mb-2" placeholder="留空则自动生成..." />
            <div v-if="kdfSaltHint" :class="['mt-1 text-xs', hintClass(kdfSaltHint)]">{{ kdfSaltHint }}</div>
            <div v-if="kdf.salt" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-200 border-amber-400/30 bg-amber-400/10">
                {{ (kdf.salt.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div v-if="['HKDF-SHA256','HKDF-SHA512'].includes(kdf.algorithm)">
            <Input v-model="kdf.info" label="Info (hex, 可选)" class="font-mono ck-trim-space mb-2" />
            <div v-if="kdfInfoHint" :class="['mt-1 text-xs', hintClass(kdfInfoHint)]">{{ kdfInfoHint }}</div>
            <div v-if="kdf.info" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-200 border-amber-400/30 bg-amber-400/10">
                {{ (kdf.info.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div v-if="['PBKDF2-SHA1','PBKDF2-SHA256','PBKDF2-SHA512'].includes(kdf.algorithm)">
              <Input v-model.number="kdf.iterations" label="迭代次数" type="number" placeholder="100000" />
            </div>
            <div v-if="kdf.algorithm === 'bcrypt'">
              <Input v-model.number="kdf.cost" label="Cost (4-31)" type="number" min="4" max="31" placeholder="12" />
            </div>
            <div v-if="!['bcrypt'].includes(kdf.algorithm)">
              <Input v-model.number="kdf.keyLen" label="输出长度(字节)" type="number" placeholder="32" />
            </div>
          </div>
          <!-- Argon2 params -->
          <div v-if="kdf.algorithm.startsWith('Argon2')" class="grid grid-cols-3 gap-2 mt-2">
            <div>
              <Input v-model.number="kdf.time" label="Time" type="number" placeholder="3" />
            </div>
            <div>
              <Input v-model.number="kdf.memory" label="Memory(KB)" type="number" placeholder="65536" />
            </div>
            <div>
              <Input v-model.number="kdf.threads" label="Threads" type="number" placeholder="4" />
            </div>
          </div>
          <!-- scrypt params -->
          <div v-if="kdf.algorithm === 'scrypt'" class="grid grid-cols-3 gap-2 mt-2">
            <div>
              <Input v-model.number="kdf.n" label="N (CPU/Mem)" type="number" placeholder="32768" />
            </div>
            <div>
              <Input v-model.number="kdf.r" label="r (Block)" type="number" placeholder="8" />
            </div>
            <div>
              <Input v-model.number="kdf.p" label="p (Parallel)" type="number" placeholder="1" />
            </div>
          </div>
          <Button variant="primary" block @click="deriveKey" class="mt-3">
            <KeyIcon class="w-3.5 h-3.5" /> 派生密钥
          </Button>
        </Card>
      </div>
      <div class="space-y-3">
        <Card title="派生密钥结果">
          <ResultArea
            :modelValue="kdfResult.data"
            :error="kdfResult.error"
            :success="kdfResult.success"
            label="派生密钥"
            copyable
          />
          <div v-if="kdfResult.extra" class="mt-2">
            <label class="input-label text-amber-200">使用的Salt</label>
            <div class="result-area !min-h-0 text-amber-200 text-xs">{{ kdfResult.extra }}</div>
          </div>
        </Card>
        <Card title="安全建议">
          <div class="text-xs space-y-1.5" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <p>🔐 <strong>密码存储</strong>: 推荐 Argon2id > bcrypt > scrypt</p>
            <p>🔑 <strong>密钥派生</strong>: 推荐 HKDF-SHA256 (RFC 5869)</p>
            <p>📁 <strong>加密密钥</strong>: PBKDF2-SHA256 (迭代≥100000)</p>
            <p>⚠️ Argon2id: time=3, mem=64MB, threads=4</p>
          </div>
        </Card>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { storeToRefs } from 'pinia'
import { ShieldHalfIcon, ShieldCheckIcon, KeyIcon } from 'lucide-vue-next'
import Card from '../components/Card.vue'
import Input from '../components/Input.vue'
import Button from '../components/Button.vue'
import ResultArea from '../components/ResultArea.vue'
import AlgorithmPrinciple from '../components/AlgorithmPrinciple.vue'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import Dropdown from '../components/Dropdown.vue'
import { ComputeMAC, DeriveKey } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const { isDark } = storeToRefs(useAppStore())
const tabs = [{ id: 'mac', label: 'MAC' }, { id: 'kdf', label: 'KDF' }]
const activeTab = ref('mac')
const showPrinciple = ref(false)

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

const principles = {
  'mac': {
    title: 'MAC (消息认证码) 原理',
    content: '设计目标: 验证消息的完整性和真实性，防止消息被篡改或伪造。\n核心机制: 使用共享密钥和消息生成认证标签 (Tag)，接收方用相同密钥验证。\n常见算法:\n• CMAC: 基于 AES 分组密码，NIST 标准。\n• GMAC: GCM 的认证部分，可并行处理。\n• Poly1305: 一次性 MAC，常与 ChaCha20 配合。\n• SipHash-2-4: 为哈希表设计的快速 MAC。\n应用场景: API 签名、数据完整性校验、安全通信协议。'
  },
  'kdf': {
    title: 'KDF (密钥派生函数) 原理',
    content: '设计目标: 从密码或主密钥派生出加密密钥，增加破解难度。\n核心机制: 通过盐值 (Salt)、迭代次数、内存消耗等参数增加计算成本。\n常见算法:\n• PBKDF2: 最广泛使用的标准，通过多次迭代增加强度。\n• HKDF: 基于 HMAC 的密钥派生，适合已有高熵密钥的场景。\n• bcrypt/scrypt/Argon2: 密码哈希专用，抗暴力破解。\n安全建议: 密码存储推荐 Argon2id，密钥派生推荐 HKDF。'
  }
}
const currentPrinciple = computed(() => {
  return principles[activeTab.value] || { title: '', content: '' }
})
const parsedPrinciples = computed(() => {
  if (!currentPrinciple.value) return []
  const lines = currentPrinciple.value.content.split('\n')
  const sections = []
  let currentSection = null

  lines.forEach(line => {
    if (line.includes(':') && !line.startsWith('•')) {
      const [title, ...rest] = line.split(':')
      currentSection = { title: title.trim(), content: [rest.join(':').trim()] }
      sections.push(currentSection)
    } else if (currentSection) {
      if (line.trim()) currentSection.content.push(line.trim())
    }
  })

  if (sections.length === 0) {
    return [{ title: '详细说明', content: lines.filter(l => l.trim()) }]
  }
  return sections
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
  return 'text-amber-200'
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
