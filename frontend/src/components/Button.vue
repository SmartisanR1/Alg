<template>
  <button
    :class="[
      'btn',
      variantClass,
      size === 'xs' ? 'btn-xs' :
      size === 'sm' ? 'btn-sm' : 
      size === 'lg' ? 'btn-lg' : 'btn-md',
      { 'w-full': block }
    ]"
    :disabled="disabled"
    @click="$emit('click', $event)"
  >
    <slot />
  </button>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  variant: {
    type: String,
    default: 'primary',
    validator: (value) => ['primary', 'success', 'warning', 'secondary', 'tool', 'icon', 'download'].includes(value)
  },
  size: {
    type: String,
    default: 'md',
    validator: (value) => ['xs', 'sm', 'md', 'lg'].includes(value)
  },
  disabled: {
    type: Boolean,
    default: false
  },
  block: {
    type: Boolean,
    default: false
  }
})

defineEmits(['click'])

const variantClass = computed(() => `btn-${props.variant}`)
</script>

<style scoped>
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  white-space: nowrap;
}

.btn-xs {
  padding: 3px 6px;
  font-size: 10px;
  border-radius: 4px;
}

.btn-sm {
  padding: 6px 12px;
  font-size: 11px;
  border-radius: 6px;
}

.btn-md {
  padding: 8px 16px;
  font-size: 12px;
  border-radius: 6px;
}

.btn-lg {
  padding: 10px 20px;
  font-size: 13px;
  border-radius: 8px;
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>
