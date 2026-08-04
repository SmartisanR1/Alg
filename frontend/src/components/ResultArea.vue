<template>
  <div class="result-area-wrapper">
    <div class="result-header">
      <label class="input-label">{{ label }}</label>
      <button v-if="copyable" class="ck-copy-btn" @click="copyToClipboard(modelValue)">
        <CopyIcon class="w-3 h-3" /> 复制
      </button>
    </div>
    <div class="result-area" :class="{ 'result-success': success, 'result-error': error, 'has-badge': !!modelValue }">
      <span class="result-value">{{ modelValue || placeholder }}</span>
      <span v-if="modelValue" class="ck-byte-badge">{{ byteCount }} bytes</span>
    </div>
    <div v-if="error" class="result-error-message">
      {{ error }}
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { CopyIcon } from '@lucide/vue'
import { copyToClipboard } from '../utils/clipboard'

const props = defineProps({
  modelValue: {
    type: String,
    default: ''
  },
  label: {
    type: String,
    default: '运算结果'
  },
  placeholder: {
    type: String,
    default: '等待运算结果...'
  },
  copyable: {
    type: Boolean,
    default: false
  },
  success: {
    type: Boolean,
    default: false
  },
  error: {
    type: String,
    default: ''
  }
})

// 判断是否为十六进制: 偶数长度且只含 hex 字符
const isHex = computed(() => {
  const v = String(props.modelValue || '').replace(/\s+/g, '')
  return v.length > 0 && v.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(v)
})

const byteCount = computed(() => {
  if (!props.modelValue) return 0
  const v = String(props.modelValue).replace(/\s+/g, '')
  if (isHex.value) return v.length / 2
  return new TextEncoder().encode(props.modelValue).length
})
</script>

<style scoped>
.result-area-wrapper {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.result-area {
  position: relative;
}

.result-area.has-badge {
  padding-bottom: 30px;
}

.result-value {
  display: block;
  word-break: break-all;
}


.result-success {
  color: var(--success, #22c55e);
}

.result-error {
  color: var(--error, #ef4444);
}

.result-error-message {
  font-size: 11px;
  color: var(--error, #ef4444);
  display: flex;
  align-items: center;
  gap: 4px;
}
</style>
