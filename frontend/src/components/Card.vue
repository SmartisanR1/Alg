<template>
  <div class="card" :class="{ 'card-hoverable': hoverable }">
    <div v-if="title" class="card-header">
      <h3 class="card-title">{{ title }}</h3>
      <p v-if="subtitle" class="card-subtitle">{{ subtitle }}</p>
    </div>
    <div class="card-content">
      <slot />
    </div>
  </div>
</template>

<script setup>
defineProps({
  title: {
    type: String,
    default: ''
  },
  subtitle: {
    type: String,
    default: ''
  },
  hoverable: {
    type: Boolean,
    default: false
  }
})
</script>

<style scoped>
.card-header {
  margin-bottom: 12px;
}

.card-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text, #e4e4f0);
  margin: 0;
  letter-spacing: -0.01em;
}

.card-subtitle {
  font-size: 11px;
  color: var(--muted, #a0a0b0);
  margin: 4px 0 0 0;
}

.card-hoverable:hover {
  border-color: var(--accent, #7c5cfc);
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}
</style>
