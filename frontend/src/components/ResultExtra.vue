<template>
  <div v-if="model" class="animate-in fade-in zoom-in-95 duration-200">
    <div class="flex items-center justify-between mb-1">
      <label class="input-label !mb-0 text-cyan-400">{{ label }}</label>
      <button class="ck-copy-btn" @click="copyToClipboard(model)">
        <CopyIcon class="w-3 h-3" /> 复制
      </button>
    </div>
    <div class="relative">
      <div class="result-area !min-h-0 pb-7 text-cyan-300">{{ model }}</div>
      <ByteBadge :model-value="model" />
    </div>
  </div>
</template>

<script setup>
import { CopyIcon } from '@lucide/vue'
import ByteBadge from './ByteBadge.vue'
import { copyToClipboard } from '../utils/clipboard'

const model = defineModel({ type: String, default: '' })

defineProps({
  label: { type: String, default: '' }
})
</script>
