<template>
  <PageLayout title="文件加解密" subtitle="AES-256-GCM 文件加密 · SHA256/SM3 文件哈希 · 拖拽支持"
              icon-bg="bg-indigo-500/20">
    <template #icon>
      <FileIcon class="w-4 h-4 text-indigo-400" />
    </template>

    <div class="grid grid-cols-2 gap-4">
      <!-- File Hash -->
      <div class="space-y-3 ck-right-panel">
        <div class="ck-card">
          <p class="ck-section-title">文件哈希计算</p>
          <div class="border-2 border-dashed rounded-lg p-6 text-center transition-all"
               :class="[isDark ? 'border-dark-border hover:border-dark-accent/50' : 'border-light-border hover:border-light-accent/50',
                        hashDrag ? (isDark ? 'border-dark-accent bg-dark-accent/5' : 'border-light-accent bg-light-accent/5') : '']"
               @dragover.prevent="hashDrag = true"
               @dragleave="hashDrag = false"
               @drop.prevent="onHashFileDrop">
            <FileIcon class="w-8 h-8 mx-auto mb-2" :class="isDark ? 'text-dark-muted' : 'text-light-muted'" />
            <p class="text-sm" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
              {{ hashFile ? hashFile.name : '拖拽文件到此处' }}
            </p>
            <p class="text-xs mt-1" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">或</p>
            <button class="ck-btn-secondary mt-2 cursor-pointer inline-flex" @click="handleSelectFile">
              <FolderOpenIcon class="w-3.5 h-3.5" /> 选择文件
            </button>
          </div>
          <div class="mt-3">
            <label class="ck-label">哈希算法 (可多选)</label>
            <div class="flex flex-wrap gap-1.5">
              <button v-for="a in fileHashAlgos" :key="a"
                      class="px-2 py-1 text-xs rounded-md border transition-all"
                      :class="selectedFileAlgos.includes(a)
                        ? (isDark ? 'bg-violet-500/20 border-violet-500 text-violet-300' : 'bg-violet-100 border-violet-300 text-violet-700')
                        : (isDark ? 'border-dark-border text-dark-muted hover:border-dark-accent/50' : 'border-light-border text-light-muted hover:border-light-accent/50')"
                      @click="toggleFileAlgo(a)">
                {{ a }}
              </button>
            </div>
          </div>
          <button @click="computeFileHash" :disabled="!hashFile" class="ck-btn-primary w-full justify-center mt-3">
            <HashIcon class="w-3.5 h-3.5" /> 计算文件哈希
          </button>
        </div>

        <!-- Hash results -->
        <div v-if="fileHashResults.length > 0" class="ck-card space-y-2">
          <p class="ck-section-title">哈希结果</p>
          <div v-for="r in fileHashResults" :key="r.algo" class="flex items-center justify-between">
            <span class="ck-badge-cyan font-mono text-[11px] w-16">{{ r.algo }}</span>
            <div class="flex-1 mx-2 font-mono text-xs truncate" :class="isDark ? 'text-dark-text' : 'text-light-text'">
              {{ r.data || r.error }}
            </div>
            <button @click="copy(r.data)" class="ck-copy-btn shrink-0"><CopyIcon class="w-3 h-3" /></button>
          </div>
        </div>
      </div>

      <!-- File Encrypt/Decrypt -->
      <div class="space-y-3">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">文件加解密</p>
          <p class="text-xs" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            使用 AES-256-GCM 进行认证加密，随机生成 Nonce，提供完整性保护
          </p>

          <!-- Input file -->
          <div>
            <label class="ck-label">输入文件路径</label>
            <div class="flex gap-2">
              <input v-model="fileEnc.inputPath" class="ck-input flex-1 text-xs" placeholder="/path/to/file" />
              <button @click="selectEncryptInput" class="ck-btn-secondary shrink-0">
                <FolderOpenIcon class="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          <!-- Output file -->
          <div>
            <label class="ck-label">输出文件路径</label>
            <div class="flex gap-2">
              <input v-model="fileEnc.outputPath" class="ck-input flex-1 text-xs" placeholder="/path/to/output.enc" />
              <button @click="selectEncryptOutput" class="ck-btn-secondary shrink-0">
                <FolderOpenIcon class="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          <!-- Key -->
          <div>
            <div class="flex justify-between mb-1">
              <label class="ck-label !mb-0">加密密钥 (hex, 32字节=256位)</label>
              <button @click="genEncKey" class="text-xs text-violet-400">⚡ 生成</button>
            </div>
            <input v-model="fileEnc.key" class="ck-input font-mono ck-trim-space text-xs" placeholder="64位hex..." />
            <div v-if="fileEnc.key" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (fileEnc.key.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>

          <div class="flex gap-2">
            <button @click="encryptFile" :disabled="!fileEnc.inputPath || !fileEnc.key"
                    class="ck-btn-primary flex-1 justify-center">
              <LockIcon class="w-3.5 h-3.5" /> 加密文件
            </button>
            <button @click="decryptFile" :disabled="!fileEnc.inputPath || !fileEnc.key"
                    class="ck-btn-secondary flex-1 justify-center">
              <UnlockIcon class="w-3.5 h-3.5" /> 解密文件
            </button>
          </div>
        </div>

        <div class="ck-card">
          <CryptoPanel v-model="fileEncResult.data" label="操作结果" type="result"
                       :success="fileEncResult.success" />
          <div v-if="fileEncResult.error" class="mt-2 text-xs text-red-400">{{ fileEncResult.error }}</div>
        </div>

        <div class="ck-card">
          <p class="ck-section-title">加密格式说明</p>
          <div class="text-xs space-y-1" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <p>📦 输出格式: [12字节Nonce][密文+16字节GCM Tag]</p>
            <p>🔒 算法: AES-256-GCM (AEAD认证加密)</p>
            <p>✅ 提供: 机密性 + 完整性 + 认证</p>
            <p>🔑 密钥: 随机生成 256位密钥</p>
          </div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { storeToRefs } from 'pinia'
import { FileIcon, FolderOpenIcon, HashIcon, LockIcon, UnlockIcon, CopyIcon } from 'lucide-vue-next'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import { HashFile, EncryptFile, DecryptFile, SelectFile } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const fileHashAlgos = ['MD5', 'SHA1', 'SHA256', 'SHA512', 'SM3', 'BLAKE3']
const selectedFileAlgos = ref(['SHA256', 'SM3'])
const hashFile = ref(null)
const hashFilePath = ref('')
const hashDrag = ref(false)
const fileHashResults = ref([])

function toggleFileAlgo(a) {
  const idx = selectedFileAlgos.value.indexOf(a)
  if (idx >= 0) selectedFileAlgos.value.splice(idx, 1)
  else selectedFileAlgos.value.push(a)
}

function onHashFileDrop(e) {
  hashDrag.value = false
  const file = e.dataTransfer.files[0]
  if (file) {
    hashFile.value = file
    hashFilePath.value = file.path || ''
  }
}

async function handleSelectFile() {
  const path = await SelectFile()
  if (path) {
    hashFilePath.value = path
    hashFile.value = { name: path.split(/[\\/]/).pop() }
  }
}

async function computeFileHash() {
  if (!hashFilePath.value) return
  fileHashResults.value = []
  for (const algo of selectedFileAlgos.value) {
    try {
      const r = await HashFile({ filePath: hashFilePath.value, algorithm: algo })
      fileHashResults.value.push({ algo, data: r.data, error: r.error })
    } catch (e) {
      fileHashResults.value.push({ algo, error: String(e) })
    }
  }
}

async function selectEncryptInput() {
  const path = await SelectFile()
  if (path) fileEnc.inputPath = path
}

async function selectEncryptOutput() {
  const path = await SelectFile()
  if (path) fileEnc.outputPath = path
}

const fileEnc = reactive({ inputPath: '', outputPath: '', key: '', algorithm: 'AES-256-GCM' })
const fileEncResult = reactive({ data: '', error: '', success: null })

async function encryptFile() {
  fileEncResult.data = ''; fileEncResult.error = ''; fileEncResult.success = null
  try {
    const r = await EncryptFile({
      key: fileEnc.key,
      inputPath: fileEnc.inputPath,
      outputPath: fileEnc.outputPath
    })
    fileEncResult.data = r.data; fileEncResult.error = r.error; fileEncResult.success = r.success
  } catch (e) { fileEncResult.error = String(e); fileEncResult.success = false }
}

async function decryptFile() {
  fileEncResult.data = ''; fileEncResult.error = ''; fileEncResult.success = null
  try {
    const r = await DecryptFile({
      key: fileEnc.key,
      inputPath: fileEnc.inputPath,
      outputPath: fileEnc.outputPath
    })
    fileEncResult.data = r.data; fileEncResult.error = r.error; fileEncResult.success = r.success
  } catch (e) { fileEncResult.error = String(e); fileEncResult.success = false }
}

function genEncKey() {
  const b = new Uint8Array(32); crypto.getRandomValues(b)
  fileEnc.key = Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('').toUpperCase()
}

async function copy(t) {
  if (!t) return
  await navigator.clipboard.writeText(t)
  store.showToast('已复制')
}
</script>
