<template>
  <div class="input-wrapper">
    <label v-if="label" class="input-label">{{ label }}</label>
    <div class="input-badge-box" :class="{ 'has-badge': showBytes }">
      <input
        :type="type"
        :value="modelValue"
        :placeholder="placeholder"
        :disabled="disabled"
        class="input"
        @input="$emit('update:modelValue', $event.target.value)"
      />
      <ByteBadge v-if="showBytes" :model-value="modelValue" />
    </div>
    <div v-if="hint" class="input-hint">{{ hint }}</div>
  </div>
</template>

<script setup>
import ByteBadge from './ByteBadge.vue'

defineProps({
  modelValue: {
    type: [String, Number],
    default: ''
  },
  label: {
    type: String,
    default: ''
  },
  type: {
    type: String,
    default: 'text'
  },
  placeholder: {
    type: String,
    default: ''
  },
  disabled: {
    type: Boolean,
    default: false
  },
  hint: {
    type: String,
    default: ''
  },
  showBytes: {
    type: Boolean,
    default: false
  }
})

defineEmits(['update:modelValue'])
</script>

<style scoped>
.input-wrapper {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.input-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--text, #e4e4f0);
  letter-spacing: 0.02em;
  text-transform: uppercase;
}

.input-hint {
  font-size: 10px;
  color: var(--muted, #a0a0b0);
}

/* 启用字节角标时，为角标预留底部空间，避免与文本重叠 */
.input-badge-box {
  position: relative;
}

.input-badge-box.has-badge .input {
  padding-bottom: 22px;
}
</style>
