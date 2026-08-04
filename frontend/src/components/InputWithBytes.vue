<template>
  <div class="input-with-bytes">
    <label v-if="label" class="input-label">{{ label }}</label>
    <div class="input-container">
      <textarea
        v-if="type === 'textarea'"
        :value="model"
        @input="model = $event.target.value"
        :placeholder="placeholder"
        :rows="rows || 3"
        :class="['input', 'font-mono', inputClass]"
        :disabled="disabled"
      />
      <input
        v-else
        :value="model"
        @input="model = $event.target.value"
        :placeholder="placeholder"
        :type="type || 'text'"
        :class="['input', 'font-mono', inputClass]"
        :disabled="disabled"
      />
      <div v-if="model && showBytes" class="bytes-badge">
        {{ byteCount }} bytes
      </div>
    </div>
    <div v-if="hint" :class="['mt-1 text-xs', hintClass]">{{ hint }}</div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

// Vue 3.5 defineModel：最新 v-model API，自动支持 v-model.number 等修饰符
const [model, modifiers] = defineModel({
  type: [String, Number],
  default: '',
  set(value) {
    if (modifiers.number && value !== '' && value !== null && value !== undefined) {
      const n = Number(value)
      return Number.isNaN(n) ? value : n
    }
    return value
  }
})

const props = defineProps({
  label: String,
  placeholder: String,
  type: { type: String, default: 'text' },
  rows: Number,
  disabled: Boolean,
  hint: String,
  hintType: { type: String, default: 'info' },
  showBytes: { type: Boolean, default: true },
  inputClass: { type: String, default: '' },
  isHex: { type: Boolean, default: true }
})

const byteCount = computed(() => {
  if (!model.value) return 0
  const val = String(model.value).replace(/\s+/g, '')
  if (props.isHex) {
    return Math.floor(val.length / 2)
  }
  return val.length
})

const hintClass = computed(() => {
  if (props.hintType === 'error') return 'text-red-400'
  if (props.hintType === 'warning') return 'text-orange-300'
  if (props.hintType === 'success') return 'text-green-400'
  return 'text-gray-400'
})
</script>

<style scoped>
.input-with-bytes {
  width: 100%;
}

.input-container {
  position: relative;
}

.input-container .input {
  width: 100%;
  padding-bottom: 24px;
}

/* 字节角标样式统一使用全局 .bytes-badge (见 styles/components.css) */
</style>
