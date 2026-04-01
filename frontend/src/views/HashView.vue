<template>
  <PageLayout title="哈希与消息认证" subtitle="SHA-2/3 · SM3 · BLAKE3 · HMAC · KMAC"
              icon-bg="bg-emerald-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <HashIcon class="w-4 h-4 text-emerald-400" />
    </template>

    <template #extra>
      <button @click="showPrinciple = true" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-violet-500/10 text-violet-400 hover:bg-violet-500/20 transition-all text-xs font-medium border border-violet-500/20">
        <InfoIcon class="w-3.5 h-3.5" /> 算法原理
      </button>
    </template>

    <!-- Principle Modal (HQC Style) -->
    <transition name="fade">
      <div v-if="showPrinciple" class="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" @click.self="showPrinciple = false">
        <div class="ck-card max-w-2xl w-full shadow-2xl animate-in zoom-in-95 duration-200 overflow-hidden flex flex-col max-h-[85vh]" :class="isDark ? 'bg-dark-card border-dark-border' : 'bg-white border-gray-200'">
          <div class="flex justify-between items-center p-4 border-b shrink-0" :class="isDark ? 'border-dark-border' : 'border-gray-100'">
            <h3 class="text-sm font-bold flex items-center gap-2">
              <ShieldCheckIcon class="w-4 h-4 text-emerald-400" /> {{ currentPrinciple.title }}
            </h3>
            <button @click="showPrinciple = false" class="p-1 hover:bg-gray-100 dark:hover:bg-dark-hover rounded-md transition-colors">
              <XIcon class="w-4 h-4 text-dark-muted" />
            </button>
          </div>
          <div class="flex-1 overflow-y-auto p-6 custom-scrollbar">
            <div class="space-y-5">
              <div v-for="(section, idx) in parsedPrinciples" :key="idx" 
                   class="p-4 rounded-xl border transition-all hover:shadow-md"
                   :class="[
                     idx % 3 === 0 ? (isDark ? 'bg-emerald-500/5 border-emerald-500/10' : 'bg-emerald-50 border-emerald-100') :
                     idx % 3 === 1 ? (isDark ? 'bg-blue-500/5 border-blue-500/10' : 'bg-blue-50 border-blue-100') :
                     (isDark ? 'bg-violet-500/5 border-violet-500/10' : 'bg-violet-50 border-violet-100')
                   ]">
                <p class="font-bold mb-2.5 text-sm flex items-center gap-2"
                   :class="[
                     idx % 3 === 0 ? 'text-emerald-400' :
                     idx % 3 === 1 ? 'text-blue-400' :
                     'text-violet-400'
                   ]">
                  <span class="w-1.5 h-1.5 rounded-full" :class="idx % 3 === 0 ? 'bg-emerald-400' : idx % 3 === 1 ? 'bg-blue-400' : 'bg-violet-400'"></span>
                  {{ section.title }}
                </p>
                <div class="text-xs leading-relaxed space-y-2 opacity-90" :class="isDark ? 'text-dark-muted' : 'text-gray-600'">
                  <p v-for="(line, lIdx) in section.content" :key="lIdx" class="flex items-start gap-2">
                    <span v-if="line.startsWith('•')" class="mt-1.5 w-1 h-1 rounded-full bg-current shrink-0 opacity-40"></span>
                    <span>{{ line.startsWith('•') ? line.substring(1).trim() : line }}</span>
                  </p>
                </div>
              </div>
            </div>
          </div>
          <div class="p-4 border-t shrink-0 flex justify-end bg-gray-50/50 dark:bg-dark-bg/20" :class="isDark ? 'border-dark-border' : 'border-gray-100'">
            <button @click="showPrinciple = false" class="ck-btn-primary px-8 py-2 shadow-lg shadow-emerald-500/20 !bg-emerald-500 hover:!bg-emerald-600 border-none">确认并返回</button>
          </div>
        </div>
      </div>
    </transition>

    <!-- Hash -->
    <div v-if="activeTab === 'hash'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card">
          <div class="flex items-center justify-between mb-2">
            <label class="ck-label !mb-0">算法选择</label>
            <div class="flex gap-2">
              <button @click="selectedAlgos = [...hashAlgos]" class="text-[10px] text-violet-400 hover:text-violet-300">全选</button>
              <button @click="selectedAlgos = []" class="text-[10px] text-dark-muted hover:text-dark-text">清空</button>
            </div>
          </div>
          <div class="grid grid-cols-3 gap-1.5">
            <button v-for="algo in hashAlgos" :key="algo"
                    class="px-2 py-1.5 rounded-lg text-[10px] font-mono text-left transition-all duration-100 border"
                    :class="selectedAlgos.includes(algo)
                      ? (isDark ? 'bg-violet-500/20 border-violet-500/50 text-violet-300' : 'bg-violet-100 border-violet-300 text-violet-700')
                      : (isDark ? 'border-dark-border text-dark-muted hover:border-dark-accent/50 hover:text-dark-text' : 'border-light-border text-light-muted hover:border-light-accent/50 hover:text-light-text')"
                    @click="toggleAlgo(algo)">
              {{ algo }}
            </button>
          </div>
        </div>

        <div class="ck-card space-y-3">
          <div class="flex items-center justify-between">
            <label class="ck-label !mb-0">输入设置</label>
            <select v-model="hashFormat" class="bg-transparent border-none text-[10px] text-violet-400 font-bold outline-none cursor-pointer">
              <option value="text">TEXT (UTF-8)</option>
              <option value="hex">HEX</option>
            </select>
          </div>
          <CryptoPanel v-model="hashInput" label="输入数据" clearable type="textarea"
                       :placeholder="hashFormat === 'text' ? '输入待计算文本...' : '输入待计算 Hex...'" :rows="4" />
          
          <div v-if="selectedAlgos.some(a => a.startsWith('SHAKE'))" class="animate-in slide-in-from-top-2">
            <label class="ck-label text-[10px]">SHAKE 输出字节长度</label>
            <input v-model.number="shakeOut" type="number" min="1" class="ck-input text-xs" />
          </div>
        </div>

        <button @click="computeHash" class="ck-btn-primary w-full justify-center py-2.5">
          <HashIcon class="w-3.5 h-3.5" /> 批量计算摘要
        </button>
      </div>

      <div class="ck-stack h-full flex flex-col">
        <p class="ck-section-title px-1 shrink-0">摘要结果 (Digest Results)</p>
        <div class="flex-1 overflow-y-auto space-y-2 pr-1 custom-scrollbar min-h-0">
          <div v-if="hashResults.length === 0" class="ck-card text-center py-12 opacity-30 italic text-xs">
            选择左侧算法并输入数据后开始计算
          </div>
          <div v-for="r in hashResults" :key="r.algo" class="ck-card !p-3 animate-in slide-in-from-right-2">
            <div class="flex items-center justify-between mb-1.5">
              <span class="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">{{ r.algo }}</span>
              <div class="flex items-center gap-2">
                <span class="text-[9px] opacity-40 font-mono">{{ r.data?.length / 2 }} bytes</span>
                <button @click="copyResult(r.data)" class="text-violet-400 hover:text-violet-300 transition-colors">
                  <CopyIcon class="w-3 h-3" />
                </button>
              </div>
            </div>
            <div class="font-mono text-[11px] break-all leading-relaxed" :class="r.error ? 'text-red-400' : (isDark ? 'text-dark-text' : 'text-light-text')">
              {{ r.error || r.data }}
            </div>
          </div>
        </div>
        
        <!-- Algorithm Principles Card -->
        <div class="ck-card bg-gradient-to-br from-emerald-500/5 to-transparent border-emerald-500/10 shrink-0 mt-3">
          <p class="ck-section-title text-emerald-400">{{ currentPrinciple.title }}</p>
          <div class="text-[11px] space-y-2.5 leading-relaxed opacity-90" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div v-for="(p, i) in currentPrinciple.content.split('\n')" :key="i">
              <p v-if="p.startsWith('•')" class="pl-2.5 flex items-start gap-2">
                <span class="mt-1.5 w-1 h-1 rounded-full bg-emerald-400 shrink-0"></span>
                <span>{{ p.substring(1).trim() }}</span>
              </p>
              <p v-else-if="p.trim()" :class="p.includes(':') ? 'font-bold text-emerald-400/90 mt-1' : ''">{{ p }}</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- HMAC -->
    <div v-if="activeTab === 'hmac'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">HMAC 配置</p>
          <div>
            <label class="ck-label">底层哈希算法</label>
            <select v-model="hmac.algo" class="ck-select text-xs">
              <option v-for="a in hmacAlgos" :key="a">{{ a }}</option>
            </select>
          </div>
          <div>
            <div class="flex justify-between items-center mb-1">
              <label class="ck-label !mb-0">密钥 (Hex)</label>
              <button @click="genHmacKey" class="text-[10px] text-violet-400 hover:text-violet-300">⚡ 随机生成</button>
            </div>
            <input v-model="hmac.key" class="ck-input font-mono text-xs" placeholder="32字节或64字节 Hex 密钥..." />
          </div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="hmac.data" label="待处理数据 (Hex)" type="textarea" clearable :rows="4" />
        </div>
        <button @click="computeHmac" class="ck-btn-primary w-full justify-center py-2.5">
          <ShieldCheckIcon class="w-3.5 h-3.5" /> 计算消息认证码
        </button>
      </div>
      <div class="ck-stack h-full flex flex-col">
        <div class="ck-card flex-1 min-h-0 flex flex-col">
          <p class="ck-section-title">HMAC 结果</p>
          <CryptoPanel v-model="hmacResult.data" label="消息认证码 (MAC / Hex)" type="result"
                       :success="hmacResult.success" copyable />
          <div v-if="hmacResult.error" class="mt-2 text-xs text-red-400 animate-in slide-in-from-top-1">{{ hmacResult.error }}</div>
        </div>
        
        <!-- Algorithm Principles Card -->
        <div class="ck-card bg-gradient-to-br from-violet-500/5 to-transparent border-violet-500/10 shrink-0 mt-3">
          <p class="ck-section-title text-violet-400">{{ currentPrinciple.title }}</p>
          <div class="text-[11px] space-y-2.5 leading-relaxed opacity-90" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div v-for="(p, i) in currentPrinciple.content.split('\n')" :key="i">
              <p v-if="p.startsWith('•')" class="pl-2.5 flex items-start gap-2">
                <span class="mt-1.5 w-1 h-1 rounded-full bg-violet-400 shrink-0"></span>
                <span>{{ p.substring(1).trim() }}</span>
              </p>
              <p v-else-if="p.trim()" :class="p.includes(':') ? 'font-bold text-violet-400/90 mt-1' : ''">{{ p }}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { HashIcon, CopyIcon, ShieldCheckIcon, InfoIcon, XIcon } from 'lucide-vue-next'
import { storeToRefs } from 'pinia'
import { useRoute } from 'vue-router'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import { Hash, HMAC } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const route = useRoute()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'hash', label: '摘要 (Hash)' },
  { id: 'hmac', label: '认证 (HMAC)' },
]
const activeTab = ref('hash')

onMounted(() => {
  if (route.query.tab) {
    const tab = tabs.find(t => t.id === route.query.tab || (route.query.tab === 'sm3' && t.id === 'hash'))
    if (tab) activeTab.value = tab.id
  }
})

watch(() => route.query.tab, (newTab) => {
  if (newTab) {
    const tab = tabs.find(t => t.id === newTab || (newTab === 'sm3' && t.id === 'hash'))
    if (tab) activeTab.value = tab.id
  }
})

// Principles modal / info
const showPrinciple = ref(false)
const principles = {
  hash: {
    title: '哈希 (Hash) 算法原理',
    content: '设计目标: 将任意长度的输入映射为固定长度的输出（摘要）。\n核心特征:\n• 单向性: 无法从摘要还原原始数据。\n• 抗碰撞性: 很难找到两个不同的输入产生相同的摘要。\n• 雪崩效应: 输入的微小变化会导致输出产生巨大差异。\n常见算法:\n• SM3: 国密杂凑算法，256 位输出，安全强度等同于 SHA-256。\n• SHA-2/3: 国际标准，广泛用于数字签名和完整性校验。\n• BLAKE3: 极高性能的现代哈希算法。'
  },
  hmac: {
    title: 'HMAC (基于哈希的消息认证码) 原理',
    content: '设计目标: 提供消息的完整性校验和身份认证。\n核心公式: HMAC(K, m) = H((K+ ⊕ opad) || H((K+ ⊕ ipad) || m))\n工作流程:\n1. 密钥填充: 将密钥填充至哈希分组长度。\n2. 两次哈希: 结合内部填充 (ipad) 和外部填充 (opad) 进行两次哈希运算。\n优势: 比简单的 H(K || m) 更能抵抗长度扩展攻击，只要底层哈希函数安全，HMAC 就是安全的。'
  }
}
const currentPrinciple = computed(() => principles[activeTab.value])

const parsedPrinciples = computed(() => {
  if (!currentPrinciple.value) return []
  const lines = currentPrinciple.value.content.split('\n')
  const sections = []
  let currentSection = null

  lines.forEach(line => {
    if ((line.includes(':') || line.includes('：')) && !line.startsWith('•')) {
      const splitChar = line.includes(':') ? ':' : '：'
      const [title, ...rest] = line.split(splitChar)
      currentSection = { title: title.trim(), content: [rest.join(splitChar).trim()] }
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

// Hash
const hashAlgos = ['SM3', 'SHA256', 'SHA384', 'SHA512', 'SHA1', 'MD5', 'SHA3-256', 'SHA3-512', 'BLAKE3', 'SHAKE128', 'SHAKE256']
const selectedAlgos = ref(['SM3', 'SHA256'])
const hashFormat = ref('text')
const hashInput = ref('')
const shakeOut = ref(32)
const hashResults = ref([])

function toggleAlgo(a) {
  const idx = selectedAlgos.value.indexOf(a)
  if (idx === -1) selectedAlgos.value.push(a)
  else selectedAlgos.value.splice(idx, 1)
}

async function computeHash() {
  if (!hashInput.value) return
  hashResults.value = []
  for (const algo of selectedAlgos.value) {
    const r = await Hash({ algo, data: hashInput.value, format: hashFormat.value, shakeLen: shakeOut.value })
    hashResults.value.push({ algo, ...r })
  }
}

// HMAC
const hmacAlgos = ['SM3', 'SHA256', 'SHA384', 'SHA512', 'SHA1', 'MD5']
const hmac = reactive({ algo: 'SM3', key: '', data: '' })
const hmacResult = reactive({ data: '', error: '', success: null })

function genHmacKey() {
  const b = new Uint8Array(32); crypto.getRandomValues(b)
  hmac.key = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

async function computeHmac() {
  const r = await HMAC(hmac)
  hmacResult.data = r.data; hmacResult.error = r.error; hmacResult.success = r.success
}

async function copyResult(t) {
  if (!t) return
  await navigator.clipboard.writeText(t)
  store.showToast('已复制摘要')
}
</script>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 4px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: transparent;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(139, 92, 246, 0.2);
  border-radius: 10px;
}
</style>
