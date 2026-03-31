<template>
  <div class="flex items-center justify-between mb-1">
    <label class="ck-label !mb-0">{{ label }}</label>
    <div class="flex gap-1">
      <button v-if="copyable && modelValue" @click="copy" class="ck-copy-btn">
        <CheckIcon v-if="copied" class="w-3 h-3 text-emerald-400" />
        <CopyIcon v-else class="w-3 h-3" />
        {{ copied ? '已复制' : '复制' }}
      </button>
      <button v-if="clearable && modelValue" @click="$emit('update:modelValue', '')" class="ck-copy-btn">
        <XIcon class="w-3 h-3" />
        清空
      </button>
    </div>
  </div>

  <div class="relative group">
    <!-- Input/Textarea -->
    <textarea
      v-if="type === 'textarea'"
      :value="modelValue"
      @input="handleInput"
      @blur="handleBlur"
      :placeholder="placeholder"
      :readonly="readonly"
      :rows="rows || 3"
      class="ck-textarea w-full !pb-4"
      :class="[{ 'ck-textarea-sm': compact, 'cursor-default': readonly }]"
    />
    <input
      v-else-if="type === 'input'"
      :value="modelValue"
      @input="handleInput"
      @blur="handleBlur"
      :placeholder="placeholder"
      :readonly="readonly"
      class="ck-input w-full !pr-14"
      :class="{ 'ck-input-sm': compact }"
    />
    <div v-else-if="type === 'result'"
          class="ck-result cursor-text !pb-4 relative"
          :class="[
            { 'ck-result-sm': compact },
            { 'text-emerald-400': success === true, 'text-red-400': success === false }
          ]">
      <span v-if="modelValue">{{ displayValue }}</span>
      <span v-else class="ck-empty">{{ placeholder || '结果将显示在这里...' }}</span>
    </div>

    <!-- Byte Count Badge (Bottom Right) -->
    <div v-if="modelValue && showByteCount"
         class="absolute bottom-1 right-1 flex items-center gap-1 px-1 py-0.5 rounded border backdrop-blur-sm pointer-events-none transition-opacity duration-200"
         :class="[
           success === false ? 'opacity-100' : 'opacity-60 group-hover:opacity-100',
           isDark ? 'bg-dark-bg/80 border-dark-border/50 text-dark-text' : 'bg-white/80 border-light-border/50 text-light-text'
         ]">
      <div class="w-1.5 h-1.5 rounded-full" :class="isHex ? 'bg-violet-500' : 'bg-cyan-500'"></div>
      <span class="text-[8px] font-mono font-medium whitespace-nowrap">
        {{ byteCount }} bytes
      </span>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { storeToRefs } from 'pinia'
import { CopyIcon, CheckIcon, XIcon } from 'lucide-vue-next'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const props = defineProps({
  modelValue: String,
  label: String,
  placeholder: String,
  type: { type: String, default: 'textarea' },
  readonly: Boolean,
  copyable: { type: Boolean, default: false },
  clearable: { type: Boolean, default: false },
  rows: Number,
  success: { type: Boolean, default: null },
  showByteCount: { type: Boolean, default: true },
  autoTrimHex: { type: Boolean, default: true },
  compact: { type: Boolean, default: false },
})

const emit = defineEmits(['update:modelValue'])

const copied = ref(false)

const isHex = computed(() => {
  return props.label?.toLowerCase().includes('hex') || props.placeholder?.toLowerCase().includes('hex')
})

const displayValue = computed(() => {
  if (!props.modelValue) return ''
  if (props.type !== 'result') return props.modelValue
  if (!isHex.value) return props.modelValue
  const clean = props.modelValue.replace(/\\s+/g, '').toUpperCase()
  return clean.match(/.{1,4}/g)?.join(' ') || clean
})

const byteCount = computed(() => {
  if (!props.modelValue) return 0
  if (isHex.value) {
    const cleanHex = props.modelValue.replace(/\s+/g, '')
    return Math.ceil(cleanHex.length / 2)
  }
  return new TextEncoder().encode(props.modelValue).length
})

function handleInput(e) {
  let val = e.target.value
  // Don't auto-trim while typing to avoid cursor jumps, only on blur or if pasted
  // But if the user specifically asked for "自动去掉", we'll do it on input but only if the value actually changed after cleaning
  if (isHex.value && props.autoTrimHex) {
    const cleaned = val.replace(/\s+/g, '')
    if (val !== cleaned) {
      // If it contains spaces, clean it. This handles pasting well.
      // For manual typing, it's slightly aggressive but meets the requirement.
      val = cleaned
    }
  }
  emit('update:modelValue', val)
}

function handleBlur(e) {
  if (isHex.value && props.autoTrimHex) {
    const cleaned = e.target.value.replace(/\s+/g, '')
    const upper = cleaned.toUpperCase()
    emit('update:modelValue', upper)
  }
}

async function copy() {
  if (!props.modelValue) return
  await navigator.clipboard.writeText(props.modelValue)
  copied.value = true
  store.showToast('已复制')
  setTimeout(() => { copied.value = false }, 2000)
}
</script>
