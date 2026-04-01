<template>
  <PageLayout title="大数运算工具" subtitle="模加 · 模减 · 模乘 · 模幂 · 高级进制转换"
              icon-bg="bg-indigo-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <CalculatorIcon class="w-4 h-4 text-indigo-400" />
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
            <div v-for="(p, i) in currentPrinciple.content.split('\n')" :key="i">
              <p v-if="p.startsWith('•')" class="pl-2">{{ p }}</p>
              <p v-else-if="p.trim()" :class="p.includes(':') ? 'font-bold text-violet-400 mt-2' : ''">{{ p }}</p>
            </div>
          </div>
          <div class="mt-6 flex justify-end">
            <button @click="showPrinciple = false" class="ck-btn-primary px-6">确定</button>
          </div>
        </div>
      </div>
    </transition>

    <!-- Big Int Operations -->
    <div v-if="activeTab === 'bigint'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <div class="ck-card space-y-4">
          <p class="ck-section-title">模运算 (Modular Arithmetic)</p>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="ck-label">操作数 A (Hex/Dec)</label>
              <input v-model="bi.a" class="ck-input font-mono ck-trim-space" placeholder="输入 A..." />
            </div>
            <div>
              <label class="ck-label">操作数 B (Hex/Dec)</label>
              <input v-model="bi.b" class="ck-input font-mono ck-trim-space" placeholder="输入 B..." />
            </div>
          </div>
          <div>
            <label class="ck-label">模数 N (Modulus)</label>
            <input v-model="bi.n" class="ck-input font-mono ck-trim-space" placeholder="输入 N..." />
          </div>
          <div class="grid grid-cols-2 gap-2">
            <button @click="doBigIntOp('add')" class="ck-btn-primary justify-center text-xs">(A + B) mod N</button>
            <button @click="doBigIntOp('sub')" class="ck-btn-primary justify-center text-xs">(A - B) mod N</button>
            <button @click="doBigIntOp('mul')" class="ck-btn-primary justify-center text-xs">(A * B) mod N</button>
            <button @click="doBigIntOp('exp')" class="ck-btn-primary justify-center text-xs">(A ^ B) mod N</button>
          </div>
        </div>

        <div class="ck-card space-y-4">
          <p class="ck-section-title">进制转换 (高级)</p>
          <div class="grid grid-cols-2 gap-3">
             <select v-model="bi.baseFrom" class="ck-select">
               <option :value="10">十进制</option>
               <option :value="16">十六进制</option>
               <option :value="2">二进制</option>
             </select>
             <select v-model="bi.baseTo" class="ck-select">
               <option :value="10">十进制</option>
               <option :value="16">十六进制</option>
               <option :value="2">二进制</option>
             </select>
          </div>
          <button @click="doBigIntOp('base')" class="ck-btn-secondary w-full justify-center text-xs">执行转换</button>
        </div>
      </div>
      <div class="space-y-3">
        <div class="ck-card">
          <CryptoPanel v-model="biResult.data" label="运算结果" type="result" :success="biResult.success" copyable />
          <div v-if="biResult.error" class="mt-2 text-xs text-red-400">{{ biResult.error }}</div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { CalculatorIcon, InfoIcon, XIcon } from 'lucide-vue-next'
import { storeToRefs } from 'pinia'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import { BigIntOperation } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

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

// BigInt
const bi = reactive({ a: '', b: '', n: '', baseFrom: 10, baseTo: 16 })
const biResult = reactive({ data: '', error: '', success: null })

async function doBigIntOp(op) {
  const r = await BigIntOperation({ ...bi, op })
  biResult.data = r.data; biResult.error = r.error; biResult.success = r.success
}
</script>
