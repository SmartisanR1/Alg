<template>
  <span v-if="hasValue" class="ck-byte-badge">{{ byteCount }} bytes</span>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  modelValue: { type: [String, Number], default: '' },
  // null = 自动识别 hex；true = 强制按 hex；false = 强制按文本
  isHex: { type: Boolean, default: null },
})

const hasValue = computed(() => {
  const v = props.modelValue
  return v !== '' && v !== null && v !== undefined
})

const byteCount = computed(() => {
  if (!hasValue.value) return 0
  const raw = String(props.modelValue)
  const compact = raw.replace(/\s+/g, '')
  const isHexStr = compact.length > 0 && compact.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(compact)
  const hex = props.isHex ?? isHexStr
  return hex ? compact.length / 2 : new TextEncoder().encode(raw).length
})
</script>
