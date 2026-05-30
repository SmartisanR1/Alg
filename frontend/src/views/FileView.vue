<template>
  <PageLayout title="文件加解密" subtitle="AES-256-GCM 文件加密 · SHA256/SM3 文件哈希 · 拖拽支持"
              icon-bg="bg-indigo-500/20">
    <template #icon>
      <FileIcon class="w-4 h-4 text-indigo-400" />
    </template>

    <div class="grid grid-cols-2 gap-4">
      <!-- File Hash -->
      <div class="space-y-3 sym-main">
        <Card title="文件哈希计算">
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
            <Button variant="secondary" class="mt-2 cursor-pointer inline-flex" @click="handleSelectFile">
              <FolderOpenIcon class="w-3.5 h-3.5" /> 选择文件
            </Button>
          </div>
          <div class="mt-3">
            <label class="input-label">哈希算法 (可多选)</label>
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
          <Button variant="primary" block @click="computeFileHash" :disabled="!hashFile" class="mt-3">
            <HashIcon class="w-3.5 h-3.5" /> 计算文件哈希
          </Button>
        </Card>

        <!-- Hash results -->
        <div v-if="fileHashResults.length > 0" class="card space-y-2">
          <p class="card-title">哈希结果</p>
          <div v-for="r in fileHashResults" :key="r.algo" class="flex items-center justify-between">
            <span class="badge font-mono text-[11px] w-16">{{ r.algo }}</span>
            <div class="flex-1 mx-2 font-mono text-xs truncate" :class="isDark ? 'text-dark-text' : 'text-light-text'">
              {{ r.data || r.error }}
            </div>
            <Button variant="tool" size="sm" @click="copy(r.data)"><CopyIcon class="w-3 h-3" /></Button>
          </div>
        </div>
      </div>

      <!-- File Encrypt/Decrypt -->
      <div class="space-y-3">
        <Card title="文件加解密" class="space-y-3">
          <p class="text-xs" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            使用 AES-256-GCM 进行认证加密，随机生成 Nonce，提供完整性保护
          </p>

          <!-- Input file -->
          <div>
            <Input v-model="fileEnc.inputPath" label="输入文件路径" class="text-xs" placeholder="/path/to/file" />
            <Button variant="tool" class="shrink-0 mt-1" @click="selectEncryptInput">
              <FolderOpenIcon class="w-3.5 h-3.5" /> 选择文件
            </Button>
          </div>

          <!-- Output file -->
          <div>
            <Input v-model="fileEnc.outputPath" label="输出文件路径" class="text-xs" placeholder="/path/to/output.enc" />
            <Button variant="tool" class="shrink-0 mt-1" @click="selectEncryptOutput">
              <FolderOpenIcon class="w-3.5 h-3.5" /> 选择文件
            </Button>
          </div>

          <!-- Key -->
          <div>
            <div class="flex justify-between mb-1">
              <label class="input-label !mb-0">加密密钥 (hex, 32字节=256位)</label>
              <Button variant="tool" size="sm" @click="genEncKey">⚡ 生成</Button>
            </div>
            <Input v-model="fileEnc.key" class="font-mono text-xs" placeholder="64位hex..." />
            <div v-if="fileEnc.key" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (fileEnc.key.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>

          <div class="flex gap-2">
            <Button variant="success" class="flex-1 justify-center" @click="encryptFile" :disabled="!fileEnc.inputPath || !fileEnc.key">
              <LockIcon class="w-3.5 h-3.5" /> 加密文件
            </Button>
            <Button variant="warning" class="flex-1 justify-center" @click="decryptFile" :disabled="!fileEnc.inputPath || !fileEnc.key">
              <UnlockIcon class="w-3.5 h-3.5" /> 解密文件
            </Button>
          </div>
        </Card>

        <Card title="操作结果">
          <ResultArea
            :modelValue="fileEncResult.data"
            :error="fileEncResult.error"
            :success="fileEncResult.success"
            label="操作结果"
          />
        </Card>

        <Card title="加密格式说明">
          <div class="text-xs space-y-1" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <p>📦 输出格式: [12字节Nonce][密文+16字节GCM Tag]</p>
            <p>🔒 算法: AES-256-GCM (AEAD认证加密)</p>
            <p>✅ 提供: 机密性 + 完整性 + 认证</p>
            <p>🔑 密钥: 随机生成 256位密钥</p>
          </div>
        </Card>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { storeToRefs } from 'pinia'
import { FileIcon, FolderOpenIcon, HashIcon, LockIcon, UnlockIcon, CopyIcon } from 'lucide-vue-next'
import Card from '../components/Card.vue'
import Input from '../components/Input.vue'
import Button from '../components/Button.vue'
import ResultArea from '../components/ResultArea.vue'
import PageLayout from '../components/PageLayout.vue'
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
