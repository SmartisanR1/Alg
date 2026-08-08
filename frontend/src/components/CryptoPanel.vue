<template>
  <div class="flex items-center justify-between mb-1">
    <label class="input-label !mb-0">{{ label }}</label>
    <div class="flex gap-1">
      <button v-if="copyable && model" @click="copy" class="ck-copy-btn">
        <CheckIcon v-if="copied" class="w-3 h-3 text-emerald-400" />
        <CopyIcon v-else class="w-3 h-3" />
        {{ copied ? '已复制' : '复制' }}
      </button>
      <button v-if="clearable && model" @click="model = ''" class="ck-copy-btn">
        <XIcon class="w-3 h-3" />
        清空
      </button>
    </div>
  </div>

  <div class="relative group">
    <!-- Input/Textarea -->
    <textarea
      v-if="type === 'textarea'"
      :value="model"
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
      :value="model"
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
      <span v-if="model">{{ displayValue }}</span>
      <span v-else class="ck-empty">{{ placeholder || '结果将显示在这里...' }}</span>
    </div>

    <!-- 可选右上角动作按钮（如 ⚡ 生成），定位在输入框右上角 -->
    <div v-if="$slots.action" class="ck-panel-action">
      <slot name="action" />
    </div>

    <!-- Byte Count Badge (Bottom Right) -->
    <div v-if="model && showByteCount" class="ck-byte-badge">
      {{ byteCount }} bytes
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { CopyIcon, CheckIcon, XIcon } from '@lucide/vue'
import { copyToClipboard } from '../utils/clipboard'

// Vue 3.5 defineModel：最新 v-model API
const model = defineModel({ type: String })

const props = defineProps({
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
  // 智能去空格：当输入内容仅由 hex 字符和空格组成时自动去掉空格（便于粘贴带空格的 hex 数据）
  trimHexSpaces: { type: Boolean, default: false },
  compact: { type: Boolean, default: false },
  groupHex: { type: Boolean, default: true },
})

const copied = ref(false)

const isHex = computed(() => {
  return props.label?.toLowerCase().includes('hex') || props.placeholder?.toLowerCase().includes('hex')
})

const displayValue = computed(() => {
  if (!model.value) return ''
  if (props.type !== 'result') return model.value
  if (!isHex.value) return model.value
  const clean = model.value.replace(/\s+/g, '').toUpperCase()
  if (!props.groupHex) return clean
  return clean.match(/.{1,4}/g)?.join(' ') || clean
})

const byteCount = computed(() => {
  if (!model.value) return 0
  if (isHex.value) {
    const cleanHex = model.value.replace(/\s+/g, '')
    return Math.ceil(cleanHex.length / 2)
  }
  return new TextEncoder().encode(model.value).length
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
  } else if (props.trimHexSpaces && /^[0-9a-fA-F\s]*$/.test(val) && /\S/.test(val)) {
    // 智能去空格：内容仅由 hex 字符和空格组成时自动去掉空格，便于粘贴带空格的 hex 数据
    const cleaned = val.replace(/\s+/g, '')
    if (val !== cleaned) {
      val = cleaned
    }
  }
  model.value = val
}

function handleBlur(e) {
  if (isHex.value && props.autoTrimHex) {
    const cleaned = e.target.value.replace(/\s+/g, '')
    const upper = cleaned.toUpperCase()
    model.value = upper
  }
}

async function copy() {
  const ok = await copyToClipboard(model.value)
  if (!ok) return
  copied.value = true
  setTimeout(() => { copied.value = false }, 2000)
}
</script>

<style scoped>
/* 输入框右上角动作按钮（⚡ 生成）定位：相对 .relative.group（只含输入框，不含 label），
   因此 top:50% 即输入框垂直居中，正好在输入框右上角 */
.ck-panel-action {
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  z-index: 2;
  display: flex;
  align-items: center;
}
</style>
