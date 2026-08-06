<template>
  <div class="input-wrapper">
    <label v-if="label" class="input-label">{{ label }}</label>
    <div class="input-badge-box" :class="{ 'has-badge': showBytes }">
      <input
        :type="type"
        :value="model"
        :placeholder="placeholder"
        :disabled="disabled"
        class="input"
        @input="model = $event.target.value"
      />
      <ByteBadge v-if="showBytes" :model-value="model" />
    </div>
    <div v-if="hint" class="input-hint">{{ hint }}</div>
  </div>
</template>

<script setup>
import ByteBadge from './ByteBadge.vue'

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

defineProps({
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
</script>

<style scoped>
.input-wrapper {
  display: flex;
  flex-direction: column;
}

.input-hint {
  font-size: 10px;
  color: var(--muted, #a0a0b0);
  margin-top: 4px;
}

/* 启用字节角标时，为角标预留底部空间，避免与文本重叠 */
.input-badge-box {
  position: relative;
}

.input-badge-box.has-badge .input {
  padding-bottom: 22px;
}
</style>
