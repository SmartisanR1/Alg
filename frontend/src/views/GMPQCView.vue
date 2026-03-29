<template>
  <PageLayout title="国密后量子密码 (GM-PQC)" subtitle="基于格的国密 PQC 算法调研与实验"
              icon-bg="bg-red-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <ZapIcon class="w-4 h-4 text-red-400" />
    </template>

    <div class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <div class="ck-card">
          <p class="ck-section-title">算法调研状态</p>
          <p class="text-sm text-dark-muted leading-relaxed">
            目前国内正在积极开展后量子密码算法的标准制定工作。主要方向包括：
          </p>
          <ul class="mt-3 space-y-2 text-xs text-dark-text list-disc list-inside">
            <li>基于格的签名算法 (类似 Dilithium)</li>
            <li>基于格的密钥封装 (类似 Kyber)</li>
            <li>基于编码的密码体制</li>
          </ul>
          <div class="mt-4 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-[10px] text-red-400">
            ⚠️ 当前处于学术调研阶段，暂无正式发布的国密标准 PQC 算法。
          </div>
        </div>
      </div>
      
      <div class="space-y-3">
        <div class="ck-card">
          <p class="ck-section-title">实验性集成</p>
          <div class="flex flex-col items-center justify-center py-12 text-center">
            <div class="w-12 h-12 rounded-full bg-dark-bg flex items-center justify-center mb-4">
              <LockIcon class="w-6 h-6 text-dark-muted" />
            </div>
            <p class="text-xs text-dark-muted">等待国密 PQC 标准正式发布后集成</p>
          </div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref } from 'vue'
import { ZapIcon, LockIcon } from 'lucide-vue-next'
import PageLayout from '../components/PageLayout.vue'

const tabs = [
  { id: 'info', label: '调研信息' },
]
const activeTab = ref('info')
</script>
