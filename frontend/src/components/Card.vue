<template>
  <div class="card" :class="cardClasses" v-bind="otherAttrs">
    <div v-if="title" class="card-header">
      <h3 class="card-title">{{ title }}</h3>
      <p v-if="subtitle" class="card-subtitle">{{ subtitle }}</p>
    </div>
    <div class="card-content" :class="contentSpacing">
      <slot />
    </div>
  </div>
</template>

<script setup>
import { useAttrs, computed } from 'vue'

defineOptions({ inheritAttrs: false })

const props = defineProps({
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

const attrs = useAttrs()

// space-y-* 类作用于 .card-content：让卡片内容区内部子元素获得统一垂直间距。
// 原实现把这些类加在 .card 根元素上，对 .card-content 内的子元素不生效，
// 导致所有用 <Card class="space-y-*"> 的卡片内部元素紧贴——这是多处
// "框挨着太近 / 文字和框太近" 的系统性根因。
const contentSpacing = computed(() => {
  const cls = String(attrs.class || '').split(/\s+/).filter(Boolean)
  return cls.filter(c => c.startsWith('space-y-')).join(' ')
})

// 其余 class（含 hoverable）仍作用于卡片根元素
const cardClasses = computed(() => {
  const cls = String(attrs.class || '').split(/\s+/).filter(Boolean)
  const rest = cls.filter(c => !c.startsWith('space-y-'))
  return [rest, { 'card-hoverable': props.hoverable }]
})

// 其余 attrs（style/id/data-* 等）透传到根元素
const otherAttrs = computed(() => {
  const { class: _cls, ...rest } = attrs
  return rest
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
