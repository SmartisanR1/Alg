<template>
  <Teleport to="body">
    <Transition name="drawer">
      <div v-if="isOpen" class="drawer-overlay" @click.self="close">
        <div class="drawer-container" :class="{ 'drawer-dark': isDark, 'drawer-light': !isDark }">
          <div class="drawer-header">
            <div class="drawer-title">
              <component :is="icon" class="drawer-icon" :style="{ color: accentColor }" />
              <h3>{{ title }}</h3>
            </div>
            <button @click="close" class="drawer-close">
              <XIcon class="w-4 h-4" />
            </button>
          </div>
          <div class="drawer-content custom-scrollbar">
            <slot />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
import { XIcon } from 'lucide-vue-next'
import { useAppStore } from '../stores/app'
import { storeToRefs } from 'pinia'

const props = defineProps({
  isOpen: Boolean,
  title: String,
  icon: Object,
  accentColor: { type: String, default: '#7c6af7' }
})

const emit = defineEmits(['close'])

const store = useAppStore()
const { isDark } = storeToRefs(store)

const close = () => emit('close')
</script>

<style scoped>
.drawer-overlay {
  position: fixed;
  inset: 0;
  z-index: 200;
  background: rgba(0, 0, 0, 0.4);
  backdrop-filter: blur(4px);
  display: flex;
  justify-content: flex-end;
}

.drawer-container {
  width: 360px;
  max-width: 90vw;
  height: 100%;
  display: flex;
  flex-direction: column;
  box-shadow: -8px 0 32px rgba(0, 0, 0, 0.2);
}

.drawer-dark {
  background: #16161f;
  border-left: 1px solid #2a2a3e;
}

.drawer-light {
  background: #ffffff;
  border-left: 1px solid #dddded;
}

.drawer-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
}

.drawer-title {
  display: flex;
  align-items: center;
  gap: 10px;
}

.drawer-title h3 {
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
  margin: 0;
}

.drawer-icon {
  width: 18px;
  height: 18px;
}

.drawer-close {
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  color: var(--muted);
  cursor: pointer;
  border-radius: 8px;
  transition: all 0.15s ease;
}

.drawer-close:hover {
  background: var(--hover);
  color: var(--text);
}

.drawer-content {
  flex: 1;
  overflow-y: auto;
  padding: 20px;
  font-size: 12px;
  line-height: 1.7;
  color: var(--muted);
}

.drawer-content :deep(h4) {
  font-size: 12px;
  font-weight: 600;
  color: var(--text);
  margin: 16px 0 8px 0;
}

.drawer-content :deep(h4:first-child) {
  margin-top: 0;
}

.drawer-content :deep(.principle-tag) {
  display: inline-block;
  padding: 2px 8px;
  background: rgba(var(--accent-rgb), 0.15);
  color: var(--accent);
  border-radius: 4px;
  font-size: 11px;
  font-weight: 500;
  margin: 2px 0;
}

.drawer-content :deep(.principle-note) {
  padding: 10px 12px;
  background: var(--hover);
  border-radius: 8px;
  margin: 8px 0;
  font-size: 11px;
}

.drawer-content :deep(.principle-warning) {
  padding: 10px 12px;
  background: rgba(245, 158, 11, 0.1);
  border: 1px solid rgba(245, 158, 11, 0.2);
  border-radius: 8px;
  margin: 8px 0;
  font-size: 11px;
  color: #f59e0b;
}

.drawer-enter-active,
.drawer-leave-active {
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.drawer-enter-from,
.drawer-leave-to {
  opacity: 0;
}

.drawer-enter-from .drawer-container,
.drawer-leave-to .drawer-container {
  transform: translateX(100%);
}

.custom-scrollbar::-webkit-scrollbar {
  width: 4px;
}

.custom-scrollbar::-webkit-scrollbar-track {
  background: transparent;
}

.custom-scrollbar::-webkit-scrollbar-thumb {
  background: var(--border);
  border-radius: 2px;
}
</style>
