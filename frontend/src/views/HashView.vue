<template>
  <PageLayout title="哈希 / HMAC" subtitle="MD5 · SHA系列 · SHA-3 · BLAKE2/3 · RIPEMD · SM3"
              icon-bg="bg-emerald-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <HashIcon class="w-4 h-4 text-emerald-400" />
    </template>

    <!-- Hash -->
    <div v-if="activeTab === 'hash'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <div class="ck-card">
          <label class="ck-label">哈希算法</label>
          <div class="grid grid-cols-2 gap-1.5">
            <button v-for="algo in hashAlgos" :key="algo"
                    class="px-2 py-1.5 rounded-lg text-xs font-mono text-left transition-all duration-100 border"
                    :class="selectedAlgos.includes(algo)
                      ? (isDark ? 'bg-violet-500/20 border-violet-500/50 text-violet-300' : 'bg-violet-100 border-violet-300 text-violet-700')
                      : (isDark ? 'border-dark-border text-dark-muted hover:border-dark-accent/50 hover:text-dark-text' : 'border-light-border text-light-muted hover:border-light-accent/50 hover:text-light-text')"
                    @click="toggleAlgo(algo)">
              {{ algo }}
            </button>
          </div>
          <button @click="selectedAlgos = [...hashAlgos]" class="mt-2 text-xs text-violet-400 hover:text-violet-300">全选</button>
          <span class="mx-2 text-xs" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">·</span>
          <button @click="selectedAlgos = []" class="text-xs" :class="isDark ? 'text-dark-muted hover:text-dark-text' : 'text-light-muted hover:text-light-text'">清空</button>
        </div>

        <div class="ck-card">
          <label class="ck-label">输入格式</label>
          <select v-model="hashFormat" class="ck-select mb-3">
            <option value="text">文本 (UTF-8)</option>
            <option value="hex">Hex</option>
          </select>
          <CryptoPanel v-model="hashInput" label="输入数据" clearable type="textarea"
                       :placeholder="hashFormat === 'text' ? '输入文本...' : '输入hex数据...'" :rows="5" />
          <div v-if="hashLenHint" :class="['mt-1 text-xs', hintClass(hashLenHint)]">{{ hashLenHint }}</div>
          <div v-if="selectedAlgos.some(a => a.startsWith('SHAKE'))" class="mt-2">
            <label class="ck-label">SHAKE 输出长度 (字节)</label>
            <input v-model.number="shakeOut" type="number" min="1" class="ck-input" placeholder="默认: SHAKE128=32, SHAKE256=64" />
          </div>
        </div>

        <button @click="computeHash" class="ck-btn-primary w-full justify-center">
          <HashIcon class="w-3.5 h-3.5" /> 计算哈希
        </button>
      </div>

      <div class="space-y-2 ck-right-panel">
        <div class="ck-card">
          <p class="ck-section-title">算法原理</p>
          <div class="text-xs space-y-2" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-2.5 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-violet-400 mb-1">哈希函数</p>
              <p>将任意长度输入映射为固定长度摘要。</p>
              <p>具备抗碰撞、抗原像和雪崩效应。</p>
            </div>
            <div class="p-2.5 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-blue-400 mb-1">输入长度</p>
              <p>• 文本输入长度任意</p>
              <p>• Hex 输入长度需为偶数位</p>
            </div>
          </div>
        </div>
        <p class="ck-section-title">计算结果</p>
        <div v-if="hashResults.length === 0" class="ck-card text-center py-8">
          <p class="text-sm" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">选择算法并输入数据后点击计算</p>
        </div>
        <div v-for="r in hashResults" :key="r.algo" class="ck-card !p-3">
          <div class="flex items-center justify-between mb-1.5">
            <span class="ck-badge-cyan font-mono text-[11px]">{{ r.algo }}</span>
            <div class="flex gap-1.5">
              <span class="text-[10px]" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">{{ r.data?.length / 2 * 8 }}位</span>
              <button @click="copyResult(r.data)" class="ck-copy-btn">
                <CopyIcon class="w-3 h-3" />
              </button>
            </div>
          </div>
          <div class="font-mono text-xs break-all" :class="r.error ? 'text-red-400' : (isDark ? 'text-dark-text' : 'text-light-text')">
            {{ r.error || r.data }}
          </div>
        </div>
      </div>
    </div>

    <!-- HMAC -->
    <div v-if="activeTab === 'hmac'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3 ck-right-panel">
        <div class="ck-card">
          <label class="ck-label">HMAC算法</label>
          <select v-model="hmac.algo" class="ck-select">
            <option v-for="a in hmacAlgos" :key="a">{{ a }}</option>
          </select>
        </div>
        <div class="ck-card space-y-3">
          <div>
            <div class="flex justify-between mb-1">
              <label class="ck-label !mb-0">密钥 (hex)</label>
              <button @click="genHmacKey" class="text-xs text-violet-400 hover:text-violet-300">⚡ 生成</button>
            </div>
            <input v-model="hmac.key" class="ck-input font-mono ck-trim-space" placeholder="hex格式密钥..." />
            <div v-if="hmacKeyHint" :class="['mt-1 text-xs', hintClass(hmacKeyHint)]">{{ hmacKeyHint }}</div>
            <div v-if="hmac.key" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (hmac.key.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <CryptoPanel v-model="hmac.data" label="数据 (hex)" type="textarea" clearable :rows="5" />
          <div v-if="hmacLenHint" :class="['mt-1 text-xs', hintClass(hmacLenHint)]">{{ hmacLenHint }}</div>
        </div>
        <button @click="computeHmac" class="ck-btn-primary w-full justify-center">
          <ShieldCheckIcon class="w-3.5 h-3.5" /> 计算 HMAC
        </button>
      </div>
      <div class="space-y-3">
        <div class="ck-card">
          <CryptoPanel v-model="hmacResult.data" label="HMAC 结果" type="result"
                       :success="hmacResult.success" copyable />
          <div v-if="hmacResult.error" class="mt-2 text-xs text-red-400">{{ hmacResult.error }}</div>
        </div>
        <div class="ck-card">
          <p class="ck-section-title">算法原理</p>
          <div class="text-xs space-y-2" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-2.5 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-violet-400 mb-1">HMAC 结构</p>
              <p>HMAC = H( (K⊕opad) || H((K⊕ipad)||M) )。</p>
              <p>基于底层哈希函数的安全性，用于完整性校验。</p>
            </div>
            <div class="p-2.5 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-blue-400 mb-1">输入长度</p>
              <p>• 数据/密钥为 Hex 时长度需为偶数位</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { HashIcon, CopyIcon, ShieldCheckIcon } from 'lucide-vue-next'
import { storeToRefs } from 'pinia'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import { Hash, HMAC } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'hash', label: 'Hash' },
  { id: 'hmac', label: 'HMAC' },
]
const activeTab = ref('hash')

const hashAlgos = [
  'MD4', 'MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512',
  'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'SHAKE128', 'SHAKE256',
  'BLAKE2s-256', 'BLAKE3', 'RIPEMD160', 'SM3'
]
const selectedAlgos = ref(['MD5', 'SHA256', 'SHA3-256', 'SM3'])
const hashInput = ref('')
const hashFormat = ref('hex')
const hashResults = ref([])
const shakeOut = ref(0)
const hashLenHint = computed(() => {
  if (hashFormat.value !== 'hex') return ''
  const clean = (hashInput.value || '').replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'Hex 长度必须为偶数位'
  return ''
})

function toggleAlgo(algo) {
  const idx = selectedAlgos.value.indexOf(algo)
  if (idx >= 0) selectedAlgos.value.splice(idx, 1)
  else selectedAlgos.value.push(algo)
}

function toHexInput(data) {
  if (hashFormat.value === 'hex') return data
  return Array.from(new TextEncoder().encode(data)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase()
}

async function computeHash() {
  hashResults.value = []
  const hexData = toHexInput(hashInput.value)
  for (const algo of selectedAlgos.value) {
    try {
      const outSize = algo.startsWith('SHAKE') ? (shakeOut.value || 0) : 0
      const r = await Hash({ algorithm: algo, data: hexData, outputSize: outSize })
      hashResults.value.push({ algo, data: r.data, error: r.error })
    } catch (e) {
      hashResults.value.push({ algo, error: String(e) })
    }
  }
}

const hmacAlgos = [
  'HMAC-MD5', 'HMAC-SHA1', 'HMAC-SHA224', 'HMAC-SHA256',
  'HMAC-SHA384', 'HMAC-SHA512', 'HMAC-SHA3-256', 'HMAC-SHA3-512',
  'HMAC-BLAKE2b-256', 'HMAC-BLAKE2b-512', 'HMAC-SM3',
]
const hmac = reactive({ algo: 'HMAC-SHA256', key: '', data: '' })
const hmacResult = reactive({ data: '', error: '', success: null })
const hmacLenHint = computed(() => {
  const clean = (hmac.data || '').replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'Hex 长度必须为偶数位'
  return ''
})
const hmacKeyHint = computed(() => {
  const clean = (hmac.key || '').replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) return '密钥 Hex 长度必须为偶数位'
  return ''
})

function hintClass(text) {
  if (!text) return ''
  if (text.includes('必须') || text.includes('需') || text.includes('应为')) return 'text-red-400'
  return 'text-amber-400'
}

async function computeHmac() {
  try {
    const r = await HMAC({ algorithm: hmac.algo, key: hmac.key, data: hmac.data })
    hmacResult.data = r.data; hmacResult.error = r.error; hmacResult.success = r.success
  } catch (e) { hmacResult.error = String(e) }
}

function genHmacKey() {
  const b = new Uint8Array(32); crypto.getRandomValues(b)
  hmac.key = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

async function copyResult(data) {
  if (!data) return
  await navigator.clipboard.writeText(data)
  store.showToast('已复制')
}
</script>
