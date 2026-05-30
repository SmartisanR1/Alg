<template>
  <div class="input-with-bytes">
    <label v-if="label" class="input-label">{{ label }}</label>
    <div class="input-container">
      <textarea
        v-if="type === 'textarea'"
        :value="modelValue"
        @input="$emit('update:modelValue', $event.target.value)"
        :placeholder="placeholder"
        :rows="rows || 3"
        :class="['input', 'font-mono', inputClass]"
        :disabled="disabled"
      />
      <input
        v-else
        :value="modelValue"
        @input="$emit('update:modelValue', $event.target.value)"
        :placeholder="placeholder"
        :type="type || 'text'"
        :class="['input', 'font-mono', inputClass]"
        :disabled="disabled"
      />
      <div v-if="modelValue && showBytes" class="bytes-badge">
        {{ byteCount }} bytes
      </div>
    </div>
    <div v-if="hint" :class="['mt-1 text-xs', hintClass]">{{ hint }}</div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  modelValue: { type: [String, Number], default: '' },
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

defineEmits(['update:modelValue'])

const byteCount = computed(() => {
  if (!props.modelValue) return 0
  const val = String(props.modelValue).replace(/\s+/g, '')
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

.bytes-badge {
  position: absolute;
  right: 8px;
  bottom: 6px;
  font-size: 10px;
  font-family: var(--font-mono);
  padding: 2px 8px;
  background: rgba(34, 211, 238, 0.15);
  color: #67e8f9;
  border-radius: 4px;
  pointer-events: none;
}
</style>
