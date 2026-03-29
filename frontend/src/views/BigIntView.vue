<template>
  <PageLayout title="大数运算工具" subtitle="模加 · 模减 · 模乘 · 模幂 · 高级进制转换"
              icon-bg="bg-indigo-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <CalculatorIcon class="w-4 h-4 text-indigo-400" />
    </template>

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
import { ref, reactive } from 'vue'
import { CalculatorIcon } from 'lucide-vue-next'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import { BigIntOperation } from '../../wailsjs/go/main/App'

const tabs = [
  { id: 'bigint', label: '大数运算' },
]
const activeTab = ref('bigint')

// BigInt
const bi = reactive({ a: '', b: '', n: '', baseFrom: 10, baseTo: 16 })
const biResult = reactive({ data: '', error: '', success: null })

async function doBigIntOp(op) {
  const r = await BigIntOperation({ ...bi, op })
  biResult.data = r.data; biResult.error = r.error; biResult.success = r.success
}
</script>
