<template>
  <PageLayout title="哈希与消息认证" subtitle="SHA-2/3 · SM3 · BLAKE3 · HMAC · KMAC"
              icon-bg="bg-emerald-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <HashIcon class="w-4 h-4 text-emerald-400" />
    </template>

    <template #extra>
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
              type="hash"
              :sections="parsedPrinciples"
            />
          </div>
          <div class="p-4 border-t shrink-0 flex justify-end bg-gray-50/50 dark:bg-dark-bg/20">
            <Button variant="primary" @click="showPrinciple = false">确认并返回</Button>
          </div>
        </div>
      </div>
    </transition>

    <!-- Hash -->
    <div v-if="activeTab === 'hash'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="算法选择">
          <div class="flex items-center justify-between mb-2">
            <div class="flex gap-2">
              <Button variant="tool" size="sm" @click="selectedAlgos = [...hashAlgos]">全选</Button>
              <Button variant="tool" size="sm" @click="selectedAlgos = []">清空</Button>
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
        </Card>

        <Card title="输入设置">
          <div class="flex items-center justify-between mb-2">
            <Dropdown
              v-model="hashFormat"
              :options="[
                { value: 'text', label: 'TEXT (UTF-8)' },
                { value: 'hex', label: 'HEX' }
              ]"
            />
          </div>
          <CryptoPanel v-model="hashInput" label="输入数据" clearable type="textarea"
                       :placeholder="hashFormat === 'text' ? '输入待计算文本...' : '输入待计算 Hex...'" :rows="4" />
          
          <div v-if="selectedAlgos.some(a => a.startsWith('SHAKE'))" class="animate-in slide-in-from-top-2">
            <Input v-model.number="shakeOut" label="SHAKE 输出字节长度" type="number" min="1" class="text-xs" />
          </div>
        </Card>

        <Button variant="success" block @click="computeHash">
          <HashIcon class="w-3.5 h-3.5" /> 批量计算摘要
        </Button>
      </div>

      <div class="sym-side h-full flex flex-col">
        <p class="card-title px-1 shrink-0">摘要结果 (Digest Results)</p>
        <div class="flex-1 overflow-y-auto space-y-2 pr-1 custom-scrollbar min-h-0">
          <div v-if="hashResults.length === 0" class="card text-center py-12 opacity-30 italic text-xs">
            选择左侧算法并输入数据后开始计算
          </div>
          <div v-for="r in hashResults" :key="r.algo" class="card !p-3 animate-in slide-in-from-right-2">
            <div class="flex items-center justify-between mb-1.5">
              <span class="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">{{ r.algo }}</span>
              <div class="flex items-center gap-2">
                <span class="text-[9px] opacity-40 font-mono">{{ r.data?.length / 2 }} bytes</span>
                <Button variant="tool" size="sm" @click="copyResult(r.data)">
                  <CopyIcon class="w-3 h-3" />
                </Button>
              </div>
            </div>
            <div class="font-mono text-[11px] break-all leading-relaxed" :class="r.error ? 'text-red-400' : (isDark ? 'text-dark-text' : 'text-light-text')">
              {{ r.error || r.data }}
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- SM3 with ID -->
    <div v-if="activeTab === 'sm3id'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="SM3(带ID与公钥) — GM/T 0003.2">
          <p class="text-[10px] opacity-60 leading-relaxed mb-3">计算 ZA = SM3(ENTLA || ID || a || b || xG || yG || xA || yA)，再计算 e = SM3(ZA || M)</p>
          <Input v-model="sm3id.id" label="用户 ID" placeholder="默认 1234567812345678" class="font-mono text-xs" />
          <div class="mt-3">
            <div class="flex justify-between items-center mb-1">
              <label class="input-label !mb-0">SM2 公钥 (64字节裸值 X||Y 或 PEM)</label>
              <Button variant="tool" size="sm" @click="genSM2KeyForSM3">⚡ 生成SM2密钥对</Button>
            </div>
            <CryptoPanel v-model="sm3id.publicKey" type="textarea" :rows="3" clearable
                         placeholder="输入64字节裸公钥 Hex (X||Y) 或 PEM 格式..." />
            <div v-if="sm3id.rawPriv" class="mt-2 p-2 rounded-lg border text-[10px] font-mono break-all"
                 :class="isDark ? 'bg-dark-bg border-dark-border text-dark-muted' : 'bg-gray-50 border-gray-200 text-gray-500'">
              <div class="flex justify-between items-center mb-1">
                <span class="text-violet-400 font-bold">裸私钥 (32字节)</span>
                <Button variant="tool" size="sm" @click="copyResult(sm3id.rawPriv)">
                  <CopyIcon class="w-3 h-3" />
                </Button>
              </div>
              <p class="break-all text-[9px]">{{ sm3id.rawPriv }}</p>
            </div>
          </div>
        </Card>
        <Card>
          <CryptoPanel v-model="sm3id.data" label="待签名消息 (Hex)" type="textarea" clearable :rows="4"
                       placeholder="输入原始消息的 Hex 编码..." />
        </Card>
        <Button variant="success" block @click="computeSM3WithID">
          <HashIcon class="w-3.5 h-3.5" /> 计算 SM3(WithID) 摘要
        </Button>
      </div>
      <div class="sym-side h-full flex flex-col">
        <Card title="SM3(WithID) 结果">
          <ResultArea
            :modelValue="sm3idResult.data"
            :error="sm3idResult.error"
            label="SM3(WithID) 摘要"
            placeholder="等待计算..."
            copyable
          />
        </Card>
        <Card class="bg-gradient-to-br from-amber-500/5 to-transparent border-amber-500/10">
          <p class="card-title text-amber-400">SM2 签名预处理说明</p>
          <div class="text-[11px] space-y-2.5 leading-relaxed opacity-90" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <p>GM/T 0003.2 规定 SM2 签名前需计算消息摘要：</p>
            <p class="pl-2.5 flex items-start gap-2">
              <span class="mt-1.5 w-1 h-1 rounded-full bg-amber-400 shrink-0"></span>
              <span>ZA 包含用户ID、曲线参数和公钥信息</span>
            </p>
            <p class="pl-2.5 flex items-start gap-2">
              <span class="mt-1.5 w-1 h-1 rounded-full bg-amber-400 shrink-0"></span>
              <span>默认ID为 "1234567812345678" (16字节)</span>
            </p>
            <p class="pl-2.5 flex items-start gap-2">
              <span class="mt-1.5 w-1 h-1 rounded-full bg-amber-400 shrink-0"></span>
              <span>最终摘要 e 传入 SM2 签名算法进行签名</span>
            </p>
          </div>
        </Card>
      </div>
    </div>

    <!-- HMAC -->
    <div v-if="activeTab === 'hmac'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="HMAC 配置">
          <div>
            <label class="input-label">底层哈希算法</label>
            <Dropdown
              v-model="hmac.algo"
              :options="hmacAlgos.map(a => ({ value: a, label: a }))"
            />
          </div>
          <div class="mt-3">
            <div class="flex justify-between items-center mb-1">
              <label class="input-label !mb-0">密钥 (Hex)</label>
              <Button variant="tool" size="sm" @click="genHmacKey">⚡ 随机生成</Button>
            </div>
            <Input v-model="hmac.key" placeholder="32字节或64字节 Hex 密钥..." class="font-mono text-xs" />
          </div>
        </Card>
        <Card>
          <CryptoPanel v-model="hmac.data" label="待处理数据 (Hex)" type="textarea" clearable :rows="4" />
        </Card>
        <Button variant="success" block @click="computeHmac">
          <ShieldCheckIcon class="w-3.5 h-3.5" /> 计算消息认证码
        </Button>
      </div>
      <div class="sym-side h-full flex flex-col">
        <Card title="HMAC 结果">
          <ResultArea
            :modelValue="hmacResult.data"
            :error="hmacResult.error"
            :success="hmacResult.success"
            label="消息认证码 (MAC / Hex)"
            copyable
          />
        </Card>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { HashIcon, CopyIcon, ShieldCheckIcon, InfoIcon, XIcon } from 'lucide-vue-next'
import { storeToRefs } from 'pinia'
import { useRoute } from 'vue-router'
import Card from '../components/Card.vue'
import Input from '../components/Input.vue'
import Button from '../components/Button.vue'
import ResultArea from '../components/ResultArea.vue'
import AlgorithmPrinciple from '../components/AlgorithmPrinciple.vue'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import Dropdown from '../components/Dropdown.vue'
import { Hash, HMAC, SM3HashWithID, SM2GenerateRawKey } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const route = useRoute()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'hash', label: '摘要 (Hash)' },
  { id: 'sm3id', label: 'SM3(带ID)' },
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
const currentPrinciple = computed(() => principles[activeTab.value] || principles['hash'])

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
  let dataHex = hashInput.value
  if (hashFormat.value === 'text') {
    const encoder = new TextEncoder()
    const bytes = encoder.encode(hashInput.value)
    dataHex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
  }
  for (const algo of selectedAlgos.value) {
    const r = await Hash({ algorithm: algo, data: dataHex, outputSize: shakeOut.value })
    hashResults.value.push({ algo, ...r })
  }
}

// HMAC
const hmacAlgos = ['SM3', 'SHA256', 'SHA384', 'SHA512', 'SHA1', 'MD5']
const hmac = reactive({ algo: 'SM3', key: '', data: '' })
const hmacResult = reactive({ data: '', error: '', success: null })

// SM3 with ID
const sm3id = reactive({ id: '', publicKey: '', data: '', rawPriv: '' })
const sm3idResult = reactive({ data: '', error: '', success: null })

function genHmacKey() {
  const b = new Uint8Array(32); crypto.getRandomValues(b)
  hmac.key = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

async function computeHmac() {
  hmacResult.data = ''; hmacResult.error = ''; hmacResult.success = null
  const r = await HMAC({ algorithm: 'HMAC-' + hmac.algo, key: hmac.key, data: hmac.data })
  hmacResult.data = r.data; hmacResult.error = r.error; hmacResult.success = r.success
}

async function computeSM3WithID() {
  if (!sm3id.data || !sm3id.publicKey) return
  const r = await SM3HashWithID({ id: sm3id.id || '1234567812345678', publicKey: sm3id.publicKey, data: sm3id.data })
  sm3idResult.data = r.data; sm3idResult.error = r.error; sm3idResult.success = r.success
}

async function genSM2KeyForSM3() {
  const r = await SM2GenerateRawKey()
  if (r.success) {
    sm3id.publicKey = r.rawPub
    sm3id.rawPriv = r.rawPriv
    store.showToast('SM2裸密钥已生成 (公钥64B, 私钥32B)')
  }
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

.sym-workbench {
  display: grid;
  grid-template-columns: minmax(400px, 1.2fr) 1fr;
  gap: 12px;
  align-items: start;
}

.sym-side,
.sym-main {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

@media (max-width: 1080px) {
  .sym-workbench {
    grid-template-columns: 1fr;
  }
}
</style>
