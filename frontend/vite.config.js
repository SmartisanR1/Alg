import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          'vue-vendor': ['vue', 'vue-router', 'pinia'],
          'icons': ['lucide-vue-next'],
        },
      },
    },
    chunkSizeWarningLimit: 1000,
    // 优化构建
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true,
      },
    },
    // 启用 CSS 代码分割
    cssCodeSplit: true,
    // 启用源码映射（生产环境禁用）
    sourcemap: false,
  },
  // 开发服务器优化
  server: {
    // 启用预热
    warmup: {
      clientFiles: ['./src/**/*.vue'],
    },
  },
})
