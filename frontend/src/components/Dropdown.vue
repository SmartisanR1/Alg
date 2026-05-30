<template>
  <div class="dropdown-container" ref="dropdownRef">
    <button
      class="dropdown-trigger"
      :class="{ active: isOpen, error: hasError }"
      @click="toggleDropdown"
      @keydown.escape="closeDropdown"
      @keydown.enter="toggleDropdown"
      @keydown.arrow-down.prevent="openDropdown"
    >
      <span class="dropdown-value">{{ selectedLabel || placeholder }}</span>
      <ChevronDownIcon class="dropdown-arrow" :class="{ rotated: isOpen }" />
    </button>

    <transition name="dropdown">
      <div v-if="isOpen" class="dropdown-menu">
        <div class="dropdown-options">
          <button
            v-for="option in options"
            :key="option.value"
            :class="['dropdown-option', { selected: option.value === modelValue }]"
            @click="selectOption(option)"
          >
            <span class="option-label">{{ option.label }}</span>
            <CheckIcon v-if="option.value === modelValue" class="check-icon" />
          </button>
        </div>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { ChevronDownIcon, CheckIcon } from 'lucide-vue-next'

const props = defineProps({
  modelValue: {
    type: [String, Number],
    default: ''
  },
  options: {
    type: Array,
    required: true,
    validator: (value) => value.every(option => 
      option.value !== undefined && option.label !== undefined
    )
  },
  placeholder: {
    type: String,
    default: '请选择...'
  },
  hasError: {
    type: Boolean,
    default: false
  }
})

const emit = defineEmits(['update:modelValue'])

const dropdownRef = ref(null)
const isOpen = ref(false)

const selectedLabel = computed(() => {
  const option = props.options.find(opt => opt.value === props.modelValue)
  return option ? option.label : ''
})

const toggleDropdown = () => {
  isOpen.value = !isOpen.value
}

const openDropdown = () => {
  isOpen.value = true
}

const closeDropdown = () => {
  isOpen.value = false
}

const selectOption = (option) => {
  emit('update:modelValue', option.value)
  closeDropdown()
}

const handleClickOutside = (event) => {
  if (dropdownRef.value && !dropdownRef.value.contains(event.target)) {
    closeDropdown()
  }
}

onMounted(() => {
  document.addEventListener('click', handleClickOutside)
})

onUnmounted(() => {
  document.removeEventListener('click', handleClickOutside)
})
</script>

<style scoped>
.dropdown-container {
  position: relative;
  width: 100%;
}

.dropdown-trigger {
  width: 100%;
  height: 36px;
  padding: 0 12px;
  background: var(--bg);
  border: 1.5px solid var(--border);
  border-radius: var(--radius-md);
  color: var(--text);
  font-size: var(--font-base);
  font-family: var(--font-mono);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: space-between;
  transition: all 0.2s ease;
}

.dropdown-trigger:hover {
  border-color: var(--hover);
  background: var(--card);
}

.dropdown-trigger:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(var(--accent-rgb), 0.15);
}

.dropdown-trigger.active {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(var(--accent-rgb), 0.15);
}

.dropdown-trigger.error {
  border-color: var(--error);
  box-shadow: 0 0 0 3px rgba(248, 113, 113, 0.15);
}

.dropdown-value {
  flex: 1;
  text-align: left;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dropdown-arrow {
  width: 16px;
  height: 16px;
  color: var(--muted);
  transition: transform 0.2s ease;
  flex-shrink: 0;
}

.dropdown-arrow.rotated {
  transform: rotate(180deg);
}

.dropdown-menu {
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  margin-top: 4px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
  z-index: 50;
  overflow: hidden;
  backdrop-filter: blur(20px);
}

.dropdown-options {
  padding: 4px;
  max-height: 200px;
  overflow-y: auto;
}

.dropdown-option {
  width: 100%;
  padding: 8px 12px;
  background: transparent;
  border: none;
  color: var(--text);
  font-size: var(--font-base);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-radius: var(--radius-sm);
  transition: all 0.15s ease;
}

.dropdown-option:hover {
  background: var(--hover);
}

.dropdown-option.selected {
  background: rgba(var(--accent-rgb), 0.2);
  color: var(--accent);
}

.option-label {
  flex: 1;
  text-align: left;
}

.check-icon {
  width: 16px;
  height: 16px;
  color: var(--accent);
  flex-shrink: 0;
}

/* Dropdown animation */
.dropdown-enter-active,
.dropdown-leave-active {
  transition: all 0.2s ease;
}

.dropdown-enter-from,
.dropdown-leave-to {
  opacity: 0;
  transform: translateY(-4px);
}
</style>
