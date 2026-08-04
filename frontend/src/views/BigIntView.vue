<template>
  <PageLayout title="大数运算工具" subtitle="模加 · 模减 · 模乘 · 模幂 · 高级进制转换"
              icon-bg="bg-indigo-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <CalculatorIcon class="w-4 h-4 text-indigo-400" />
    </template>

    <template #actions>
      <Button variant="secondary" size="sm" @click="showPrinciple = true">
        <InfoIcon class="w-3.5 h-3.5" /> 算法原理
      </Button>
    </template>

    <!-- Algorithm Principle Drawer -->
    <AlgorithmDrawer
      :is-open="showPrinciple"
      :title="currentPrinciple.title"
      :icon="InfoIcon"
      @close="showPrinciple = false"
    >
      <div v-for="(section, idx) in parsedPrinciples" :key="idx">
        <h4>{{ section.title }}</h4>
        <p v-for="(line, lIdx) in section.content" :key="lIdx" class="principle-line">
          {{ line }}
        </p>
      </div>
    </AlgorithmDrawer>

    <!-- Big Int Operations -->
    <div v-if="activeTab === 'bigint'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <Card title="模运算 (Modular Arithmetic)" class="space-y-4">
          <div class="grid grid-cols-2 gap-3">
            <div>
              <Input v-model="bi.a" label="操作数 A (Hex/Dec)" class="font-mono" placeholder="输入 A..." />
            </div>
            <div>
              <Input v-model="bi.b" label="操作数 B (Hex/Dec)" class="font-mono" placeholder="输入 B..." />
            </div>
          </div>
          <div>
            <Input v-model="bi.n" label="模数 N (Modulus)" class="font-mono" placeholder="输入 N..." />
          </div>
          <div class="grid grid-cols-2 gap-2">
            <Button variant="success" class="justify-center text-xs" @click="doBigIntOp('add')">(A + B) mod N</Button>
            <Button variant="warning" class="justify-center text-xs" @click="doBigIntOp('sub')">(A - B) mod N</Button>
            <Button variant="primary" class="justify-center text-xs" @click="doBigIntOp('mul')">(A * B) mod N</Button>
            <Button variant="download" class="justify-center text-xs" @click="doBigIntOp('exp')">(A ^ B) mod N</Button>
          </div>
          <div v-if="biResult.data || biResult.error" class="p-3 rounded-lg border animate-in fade-in zoom-in-95 duration-200"
               :class="biResult.error ? (isDark ? 'bg-red-500/5 border-red-500/20' : 'bg-red-50 border-red-200') : (isDark ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-emerald-50 border-emerald-200')">
            <div class="flex items-center justify-between mb-1.5">
              <span class="text-[11px] font-bold" :class="biResult.success ? 'text-emerald-400' : 'text-red-400'">{{ biResult.success ? '✓ 成功' : '✕ 失败' }}</span>
              <button v-if="biResult.data" class="ck-copy-btn" @click="copy(biResult.data)"><CopyIcon class="w-3 h-3" /> 复制</button>
            </div>
            <div class="font-mono text-[11px] break-all leading-relaxed" :class="biResult.error ? 'text-red-400' : 'text-emerald-400'">{{ biResult.error || biResult.data }}</div>
          </div>
        </Card>

        <Card title="进制转换 (高级)" class="space-y-4">
          <div class="grid grid-cols-2 gap-3">
             <Dropdown
               v-model="bi.baseFrom"
               :options="[
                 { value: '10', label: '十进制' },
                 { value: '16', label: '十六进制' },
                 { value: '2', label: '二进制' }
               ]"
             />
             <Dropdown
               v-model="bi.baseTo"
               :options="[
                 { value: '10', label: '十进制' },
                 { value: '16', label: '十六进制' },
                 { value: '2', label: '二进制' }
               ]"
             />
          </div>
          <div>
            <label class="input-label">输入数据</label>
            <Input v-model="bi.baseInput" class="font-mono" placeholder="输入要转换的数据..." />
          </div>
          <Button variant="secondary" block class="text-xs" @click="doBigIntOp('base')">执行转换</Button>
          <div v-if="biBaseResult" class="result-area !min-h-0 text-emerald-400 font-mono">
            {{ biBaseResult }}
          </div>
        </Card>
      </div>
      <div class="space-y-3">
        <Card title="大数运算原理" class="flex flex-col overflow-hidden">
          <div class="space-y-2.5">
            <div class="p-3 rounded-lg border" :class="isDark ? 'bg-indigo-500/5 border-indigo-500/10' : 'bg-indigo-50 border-indigo-100'">
              <p class="text-[10px] font-bold text-indigo-400 mb-2">模运算 (Modular Arithmetic)</p>
              <div class="text-[10px] space-y-1.5 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-gray-600'">
                <p class="flex items-start gap-2"><span class="mt-1 w-1 h-1 rounded-full bg-indigo-400 shrink-0"></span><span>(A+B) mod N — 模加，结果 ∈ [0, N-1]</span></p>
                <p class="flex items-start gap-2"><span class="mt-1 w-1 h-1 rounded-full bg-indigo-400 shrink-0"></span><span>(A-B) mod N — 模减，处理负数取正</span></p>
                <p class="flex items-start gap-2"><span class="mt-1 w-1 h-1 rounded-full bg-indigo-400 shrink-0"></span><span>(A×B) mod N — 模乘，密码学基础运算</span></p>
                <p class="flex items-start gap-2"><span class="mt-1 w-1 h-1 rounded-full bg-indigo-400 shrink-0"></span><span>(A^B) mod N — 模幂，RSA 核心运算</span></p>
              </div>
            </div>
            <div class="p-3 rounded-lg border" :class="isDark ? 'bg-violet-500/5 border-violet-500/10' : 'bg-violet-50 border-violet-100'">
              <p class="text-[10px] font-bold text-violet-400 mb-2">模幂算法 (Square-and-Multiply)</p>
              <div class="text-[10px] space-y-1.5 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-gray-600'">
                <p class="flex items-start gap-2"><span class="mt-1 w-1 h-1 rounded-full bg-violet-400 shrink-0"></span><span>将指数 B 转为二进制 b_k...b_1b_0</span></p>
                <p class="flex items-start gap-2"><span class="mt-1 w-1 h-1 rounded-full bg-violet-400 shrink-0"></span><span>从左到右扫描: 每步先平方</span></p>
                <p class="flex items-start gap-2"><span class="mt-1 w-1 h-1 rounded-full bg-violet-400 shrink-0"></span><span>若 b_i=1 则再乘 A，结果取模</span></p>
                <p class="flex items-start gap-2"><span class="mt-1 w-1 h-1 rounded-full bg-violet-400 shrink-0"></span><span>时间复杂度 O(log B)，非 O(B)</span></p>
              </div>
            </div>
            <div class="p-3 rounded-lg border" :class="isDark ? 'bg-cyan-500/5 border-cyan-500/10' : 'bg-cyan-50 border-cyan-100'">
              <p class="text-[10px] font-bold text-cyan-400 mb-2">密码学应用</p>
              <div class="text-[10px] space-y-1.5 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-gray-600'">
                <p class="flex items-start gap-2"><span class="mt-1 w-1 h-1 rounded-full bg-cyan-400 shrink-0"></span><span>RSA: c = m^e mod n, m = c^d mod n</span></p>
                <p class="flex items-start gap-2"><span class="mt-1 w-1 h-1 rounded-full bg-cyan-400 shrink-0"></span><span>SM2/DH: 椭圆曲线点乘依赖模运算</span></p>
                <p class="flex items-start gap-2"><span class="mt-1 w-1 h-1 rounded-full bg-cyan-400 shrink-0"></span><span>Hex ↔ Dec: 密钥/参数无损转换</span></p>
              </div>
            </div>
          </div>
        </Card>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { CalculatorIcon, InfoIcon, XIcon, CopyIcon } from '@lucide/vue'
import { storeToRefs } from 'pinia'
import Card from '../components/Card.vue'
import Input from '../components/Input.vue'
import Button from '../components/Button.vue'
import ResultArea from '../components/ResultArea.vue'
import AlgorithmDrawer from '../components/AlgorithmDrawer.vue'
import PageLayout from '../components/PageLayout.vue'
import Dropdown from '../components/Dropdown.vue'
import { BigIntOperation } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'
import { copyToClipboard } from '../utils/clipboard'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'bigint', label: '大数运算' },
]
const activeTab = ref('bigint')

// ── 算法原理 ────────────────────────────────────────────────
const showPrinciple = ref(false)
const principles = {
  bigint: {
    title: '大数运算 (BigInt) 与密码学',
    content: '设计背景: 现代公钥密码学 (如 RSA, ECC, SM2) 的安全性建立在超大整数的数学难题之上，普通的 64 位整数无法处理这些长达数千位的数值。\n核心运算:\n• 模加/减: 在有限域内的加减法，结果始终在 [0, N-1] 范围内。\n• 模乘: 基础的大数乘法后进行取模。\n• 模幂 (Modular Exponentiation): A^B mod N。这是 RSA 的核心，通过“平方-求乘”算法 (Square-and-multiply) 高效实现。\n进制转换:\n• 在密码学中，数值常以 Hex (16进制) 存储，而数学公式通常以 Dec (10进制) 描述。大数工具提供了无损的任意精度转换。'
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

// BigInt
const bi = reactive({ a: '', b: '', n: '', baseFrom: '10', baseTo: '16', baseInput: '' })
const biResult = reactive({ data: '', error: '', success: null })
const biBaseResult = ref('')

async function doBigIntOp(op) {
  try {
    if (op === 'base') {
      const req = {
        a: bi.baseInput,
        op: 'base',
        baseFrom: parseInt(bi.baseFrom),
        baseTo: parseInt(bi.baseTo)
      }
      const r = await BigIntOperation(req)
      biBaseResult.value = (r && (r.error || r.data)) || ''
      return
    }
    const req = { a: bi.a, b: bi.b, n: bi.n, op }
    const r = await BigIntOperation(req)
    if (r) {
      biResult.data = r.data || ''
      biResult.error = r.error || ''
      biResult.success = r.success || false
    } else {
      biResult.data = ''
      biResult.error = '未返回结果'
      biResult.success = false
    }
  } catch (e) {
    console.error('BigIntOperation error:', e)
    biResult.data = ''
    biResult.error = String(e)
    biResult.success = false
  }
}

const copy = (text) => copyToClipboard(text)
</script>
