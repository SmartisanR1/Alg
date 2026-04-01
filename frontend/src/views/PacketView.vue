<template>
  <PageLayout title="报文发送 / 接收" subtitle="TCP 报文头长度 · IPv4/IPv6 · TLS/TLCP · 国密双证书 · 发送历史"
              icon-bg="bg-indigo-500/20">
    <template #icon>
      <SendIcon class="w-4 h-4 text-indigo-400" />
    </template>

    <template #extra>
       <button @click="showHelp = true" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-500/10 text-sky-400 hover:bg-sky-500/20 transition-all text-xs font-medium border border-sky-500/20">
         <InfoIcon class="w-3.5 h-3.5" /> 使用说明
       </button>
     </template>

     <!-- Principle Modal (HQC Style) -->
     <transition name="fade">
       <div v-if="showPrinciple" class="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" @click.self="showPrinciple = false">
         <div class="ck-card max-w-2xl w-full shadow-2xl animate-in zoom-in-95 duration-200 overflow-hidden flex flex-col max-h-[85vh]" :class="isDark ? 'bg-dark-card border-dark-border' : 'bg-white border-gray-200'">
           <div class="flex justify-between items-center p-4 border-b shrink-0" :class="isDark ? 'border-dark-border' : 'border-gray-100'">
             <h3 class="text-sm font-bold flex items-center gap-2">
               <InfoIcon class="w-4 h-4 text-violet-400" /> 报文联调工具说明
             </h3>
             <button @click="showPrinciple = false" class="p-1 hover:bg-gray-100 dark:hover:bg-dark-hover rounded-md transition-colors">
               <XIcon class="w-4 h-4 text-dark-muted" />
             </button>
           </div>
           <div class="flex-1 overflow-y-auto p-6 custom-scrollbar">
             <div class="space-y-5">
               <div v-for="(section, idx) in parsedPrinciples" :key="idx" 
                    class="p-4 rounded-xl border transition-all hover:shadow-md"
                    :class="[
                      idx % 3 === 0 ? (isDark ? 'bg-violet-500/5 border-violet-500/10' : 'bg-violet-50 border-violet-100') :
                      idx % 3 === 1 ? (isDark ? 'bg-emerald-500/5 border-emerald-500/10' : 'bg-emerald-50 border-emerald-100') :
                      (isDark ? 'bg-blue-500/5 border-blue-500/10' : 'bg-blue-50 border-blue-100')
                    ]">
                 <p class="font-bold mb-2.5 text-sm flex items-center gap-2"
                    :class="[
                      idx % 3 === 0 ? 'text-violet-400' :
                      idx % 3 === 1 ? 'text-emerald-400' :
                      'text-blue-400'
                    ]">
                   <span class="w-1.5 h-1.5 rounded-full" :class="idx % 3 === 0 ? 'bg-violet-400' : idx % 3 === 1 ? 'bg-emerald-400' : 'bg-blue-400'"></span>
                   {{ section.title }}
                 </p>
                 <div class="text-xs leading-relaxed space-y-2 opacity-90" :class="isDark ? 'text-dark-muted' : 'text-gray-600'">
                   <p v-for="(line, lIdx) in section.content" :key="lIdx" class="flex items-start gap-2">
                     <span v-if="line.startsWith('•')" class="mt-1.5 w-1 h-1 rounded-full bg-current shrink-0 opacity-40"></span>
                     <span>{{ line.startsWith('•') ? line.substring(1).trim() : line }}</span>
                   </p>
                 </div>
               </div>
             </div>
           </div>
           <div class="p-4 border-t shrink-0 flex justify-end bg-gray-50/50 dark:bg-dark-bg/20" :class="isDark ? 'border-dark-border' : 'border-gray-100'">
             <button @click="showPrinciple = false" class="ck-btn-primary px-8 py-2 shadow-lg shadow-violet-500/20">确认并返回</button>
           </div>
         </div>
       </div>
     </transition>

     <!-- Help Modal -->
     <transition name="fade">
       <div v-if="showHelp" class="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" @click.self="showHelp = false">
         <div class="ck-card max-w-lg w-full shadow-2xl animate-in zoom-in-95 duration-200" :class="isDark ? 'bg-dark-card border-dark-border' : 'bg-white border-gray-200'">
           <div class="flex justify-between items-center mb-4 border-b pb-3" :class="isDark ? 'border-dark-border' : 'border-gray-100'">
             <h3 class="text-sm font-bold flex items-center gap-2">
               <InfoIcon class="w-4 h-4 text-violet-400" /> 使用说明
             </h3>
             <button @click="showHelp = false" class="p-1 hover:bg-gray-100 dark:bg-dark-hover rounded-md transition-colors">
               <XIcon class="w-4 h-4 text-dark-muted" />
             </button>
           </div>
           <div class="text-xs leading-relaxed space-y-3" :class="isDark ? 'text-dark-muted' : 'text-gray-600'">
             <p class="font-bold text-violet-400">使用步骤</p>
             <p>1. 配置连接信息：填写主机地址和端口号</p>
             <p>2. 选择网络协议：IPv4 或 IPv6</p>
             <p>3. 设置安全模式：明文、TLS 或国密 TLCP</p>
             <p>4. 配置证书（如果使用安全模式）：上传 CA 证书、客户端证书和私钥</p>
             <p>5. 设置报文头长度：选择 0、1、2 或 4 字节</p>
             <p>6. 配置超时时间：设置连接和响应的等待时间（毫秒）</p>
             <p class="font-bold text-violet-400 mt-2">报文发送</p>
             <p>• 选择报文格式：HEX 或 文本</p>
             <p>• 输入报文内容：直接输入或通过外部文件加载</p>
             <p>• 点击发送请求按钮开始传输</p>
             <p class="font-bold text-violet-400 mt-2">查看结果</p>
             <p>• 查看发送和接收的字节数</p>
             <p>• 查看报文头内容（如果已配置）</p>
             <p>• 查看响应数据：支持复制和错误提示</p>
           </div>
           <div class="mt-6 flex justify-end">
             <button @click="showHelp = false" class="ck-btn-primary px-6">确定</button>
           </div>
         </div>
       </div>
     </transition>

    <div class="ck-workbench animate-fade-in">
      <!-- Left side: Connection and Security -->
      <div class="ck-stack overflow-y-auto pr-1 custom-scrollbar">
        <div class="ck-card space-y-4">
          <p class="ck-section-title">连接与协议</p>
          <div class="grid grid-cols-4 gap-2">
            <div class="col-span-3">
              <label class="ck-label">主机地址</label>
              <input v-model="packet.host" class="ck-input font-mono text-xs" placeholder="127.0.0.1" />
            </div>
            <div>
              <label class="ck-label">端口</label>
              <input v-model.number="packet.port" type="number" class="ck-input font-mono text-xs" />
            </div>
          </div>
          <div class="grid grid-cols-4 gap-2">
            <div>
              <label class="ck-label">网络</label>
              <select v-model="packet.network" class="ck-select text-[11px] !px-2">
                <option value="ipv4">IPv4</option>
                <option value="ipv6">IPv6</option>
              </select>
            </div>
            <div>
              <label class="ck-label">安全模式</label>
              <select v-model="packet.transport" class="ck-select text-[11px] !px-2">
                <option value="plain">明文</option>
                <option value="tls">TLS</option>
                <option value="tlcp">TLCP</option>
              </select>
            </div>
            <div>
              <label class="ck-label">长度头</label>
              <select v-model.number="packet.headerLength" class="ck-select text-[11px] !px-2">
                <option :value="0">无</option>
                <option :value="1">1B</option>
                <option :value="2">2B</option>
                <option :value="4">4B</option>
              </select>
            </div>
            <div>
              <label class="ck-label">超时(ms)</label>
              <input v-model.number="packet.timeoutMs" type="number" class="ck-input text-[11px] !px-2" />
            </div>
          </div>
        </div>

        <!-- TLS/TLCP Certs - Conditional -->
        <div v-if="packet.transport !== 'plain'" class="ck-card space-y-3 animate-in fade-in duration-300">
          <p class="ck-section-title">安全证书 ({{ packet.transport.toUpperCase() }})</p>
          <div class="space-y-2">
            <div class="space-y-1">
              <div class="flex justify-between items-center">
                <label class="ck-label !mb-0 text-[10px]">CA 根证书</label>
                <button @click="loadCertFile('caCert')" class="text-violet-400 hover:text-violet-300 transition-colors flex items-center gap-1 text-[9px]"><UploadIcon class="w-2.5 h-2.5" /> 上传</button>
              </div>
              <textarea v-model="packet.caCert" rows="1" class="ck-textarea !min-h-0 py-1 text-[9px] font-mono" placeholder="PEM..."></textarea>
            </div>
            <div class="grid grid-cols-2 gap-2">
              <div class="space-y-1">
                <div class="flex justify-between items-center">
                  <label class="ck-label !mb-0 text-[10px]">签名证书</label>
                  <button @click="loadCertFile('clientCert')" class="text-violet-400 hover:text-violet-300 transition-colors flex items-center gap-1 text-[9px]"><UploadIcon class="w-2.5 h-2.5" /> 上传</button>
                </div>
                <textarea v-model="packet.clientCert" rows="1" class="ck-textarea !min-h-0 py-1 text-[9px] font-mono"></textarea>
              </div>
              <div class="space-y-1">
                <div class="flex justify-between items-center">
                  <label class="ck-label !mb-0 text-[10px]">签名私钥</label>
                  <button @click="loadCertFile('clientKey')" class="text-violet-400 hover:text-violet-300 transition-colors flex items-center gap-1 text-[9px]"><UploadIcon class="w-2.5 h-2.5" /> 上传</button>
                </div>
                <textarea v-model="packet.clientKey" rows="1" class="ck-textarea !min-h-0 py-1 text-[9px] font-mono"></textarea>
              </div>
            </div>
            <div v-if="packet.transport === 'tlcp'" class="grid grid-cols-2 gap-2 animate-in slide-in-from-top-1 duration-200">
              <div class="space-y-1">
                <div class="flex justify-between items-center">
                  <label class="ck-label !mb-0 text-[10px]">加密证书</label>
                  <button @click="loadCertFile('clientEncCert')" class="text-violet-400 hover:text-violet-300 transition-colors flex items-center gap-1 text-[9px]"><UploadIcon class="w-2.5 h-2.5" /> 上传</button>
                </div>
                <textarea v-model="packet.clientEncCert" rows="1" class="ck-textarea !min-h-0 py-1 text-[9px] font-mono"></textarea>
              </div>
              <div class="space-y-1">
                <div class="flex justify-between items-center">
                  <label class="ck-label !mb-0 text-[10px]">加密私钥</label>
                  <button @click="loadCertFile('clientEncKey')" class="text-violet-400 hover:text-violet-300 transition-colors flex items-center gap-1 text-[9px]"><UploadIcon class="w-2.5 h-2.5" /> 上传</button>
                </div>
                <textarea v-model="packet.clientEncKey" rows="1" class="ck-textarea !min-h-0 py-1 text-[9px] font-mono"></textarea>
              </div>
            </div>
            <label class="flex items-center gap-2 cursor-pointer pt-1">
              <input type="checkbox" v-model="packet.insecureSkipVerify" class="rounded border-dark-border bg-dark-bg text-violet-500" />
              <span class="text-[10px] opacity-70">跳过服务端证书校验</span>
            </label>
          </div>
        </div>

        <div class="ck-card overflow-hidden flex flex-col max-h-[160px]">
          <p class="ck-section-title mb-2">历史记录 (最近 20 条)</p>
          <div v-if="!packetHistory.length" class="flex-1 flex items-center justify-center text-[11px] opacity-30 italic py-4">无记录</div>
          <div v-else class="flex-1 overflow-y-auto space-y-1 pr-1 custom-scrollbar">
            <button v-for="h in packetHistory" :key="h.id" @click="applyHistory(h)"
                    class="w-full text-left p-2 rounded-lg hover:bg-white/5 transition-all border border-transparent hover:border-dark-border flex flex-col gap-0.5 group">
              <div class="flex justify-between items-center">
                <span class="text-[10px] font-bold text-violet-400">{{ h.host }}:{{ h.port }}</span>
                <span class="text-[9px] opacity-40 group-hover:opacity-100 transition-opacity">{{ h.time }}</span>
              </div>
              <div class="text-[9px] truncate opacity-50 font-mono group-hover:opacity-80 transition-opacity">{{ h.preview }}</div>
            </button>
          </div>
        </div>
      </div>

      <!-- Right side: Data and Results -->
      <div class="ck-stack h-full flex flex-col">
        <div class="ck-card space-y-3 flex flex-col flex-1 min-h-0">
          <div class="flex items-center justify-between shrink-0">
            <p class="ck-section-title">报文发送 (Payload)</p>
            <div class="flex gap-2">
              <button @click="choosePacketFile" class="text-[10px] px-2 py-0.5 rounded-lg border border-dark-border hover:bg-white/5 transition-colors flex items-center gap-1">
                <FolderOpenIcon class="w-3 h-3" /> {{ packet.filePath ? '已选文件' : '外部文件' }}
              </button>
              <select v-model="packet.payloadFormat" class="text-[10px] bg-transparent border-none outline-none text-violet-400 font-bold cursor-pointer">
                <option value="hex">HEX</option>
                <option value="text">TEXT</option>
              </select>
            </div>
          </div>
          
          <div v-if="packet.filePath" class="px-2 py-1 rounded-lg bg-violet-500/10 border border-violet-500/20 text-[10px] flex items-center justify-between shrink-0 animate-in fade-in zoom-in-95">
            <span class="truncate font-mono opacity-80">{{ packet.filePath }}</span>
            <button @click="packet.filePath = ''" class="text-violet-400 hover:text-violet-300 px-1">✕</button>
          </div>
          
          <div class="flex-1 min-h-0">
            <textarea v-model="packet.payloadData" class="ck-textarea h-full font-mono text-xs leading-relaxed" 
                      :placeholder="packet.payloadFormat === 'hex' ? '输入 16 进制报文...' : '输入原始文本内容...'"></textarea>
          </div>

          <div class="flex gap-2 shrink-0 pt-2 border-t border-dark-border/30">
            <button @click="sendPacketNow" class="ck-btn-primary flex-1 justify-center py-2 shadow-lg shadow-violet-500/10">
              <ZapIcon class="w-3.5 h-3.5" /> 发送请求
            </button>
            <button @click="resetPacket" class="ck-btn-secondary px-3" title="重置内容"><RefreshCwIcon class="w-3.5 h-3.5" /></button>
          </div>
        </div>

        <div class="ck-card space-y-2.5 shrink-0">
          <div class="flex items-center justify-between">
            <p class="ck-section-title">响应数据 (Response)</p>
            <div class="flex gap-3 text-[10px] opacity-60 font-mono">
              <span v-if="packetResult.requestBytes" class="text-cyan-400">已发: {{ packetResult.requestBytes }}B</span>
              <span v-if="packetResult.responseBytes" class="text-emerald-400">已收: {{ packetResult.responseBytes }}B</span>
              <span v-if="packetResult.durationMs" class="text-amber-400">{{ packetResult.durationMs }}ms</span>
            </div>
          </div>
          <div class="space-y-2">
            <div v-if="packetResult.headerHex" class="space-y-1">
              <label class="text-[9px] opacity-50 uppercase tracking-widest font-bold">报文头 ({{ packet.headerLength }}B)</label>
              <div class="ck-result !min-h-0 py-1.5 font-mono text-[10px] break-all bg-dark-bg/30">{{ packetResult.headerHex }}</div>
            </div>
            <div class="space-y-1">
              <div class="flex justify-between items-center">
                <label class="text-[9px] opacity-50 uppercase tracking-widest font-bold">响应内容</label>
                <button v-if="packetResult.responseHex" @click="copy(packetResult.responseHex)" class="text-violet-400 hover:text-violet-300 transition-colors"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="ck-result !min-h-[80px] font-mono text-[11px] break-all max-h-[140px] overflow-y-auto leading-relaxed" 
                   :class="{ 'text-red-400 border-red-500/20 bg-red-500/5': packetResult.error, 'text-emerald-400/90': !packetResult.error && packetResult.responseHex }">
                {{ packetResult.error || packetResult.responseHex || '等待网络响应...' }}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { SendIcon, ZapIcon, RefreshCwIcon, FolderOpenIcon, UploadIcon, CopyIcon, InfoIcon, XIcon } from 'lucide-vue-next'
import PageLayout from '../components/PageLayout.vue'
import { SelectFile, ReadFile, SendPacket } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const showPrinciple = ref(false)
const showHelp = ref(false)

// Principle content for HQC-style modal
const principleData = ref({
  title: '报文联调工具说明',
  content: `网络与安全
• IPv4/IPv6: 自动适配地址格式。
• TLS/TLCP: 支持标准 TLS 和国密 TLCP 协议。TLCP 需配置签名和加密两套证书。
报文协议
• 长度头: 自动在报文前添加 1/2/4 字节的大端序长度前缀。
• 超时控制: 精确控制连接和响应的等待时间。
高级功能
• 文件模式: 支持发送超大文件报文，直接从磁盘流式读取，不占用前端内存。
• 历史记录: 自动保存最近 20 次成功发送的配置和报文快照。`
})

const parsedPrinciples = computed(() => {
  const lines = principleData.value.content.split('\n')
  const sections = []
  let currentSection = { title: '', content: [] }

  for (const line of lines) {
    if (line.endsWith(':') && !line.startsWith('•')) {
      if (currentSection.title) {
        sections.push({ ...currentSection })
      }
      currentSection = { title: line.slice(0, -1), content: [] }
    } else if (line.trim()) {
      currentSection.content.push(line)
    }
  }

  if (currentSection.title) {
    sections.push(currentSection)
  }

  return sections
})

const packet = reactive({
  host: '127.0.0.1',
  port: 8008,
  network: 'ipv4',
  transport: 'plain',
  serverName: '',
  insecureSkipVerify: false,
  caCert: '',
  clientCert: '',
  clientKey: '',
  clientEncCert: '',
  clientEncKey: '',
  headerLength: 4,
  timeoutMs: 5000,
  payloadData: '',
  payloadFormat: 'hex',
  filePath: ''
})

const packetResult = reactive({
  success: null,
  error: '',
  responseHex: '',
  headerHex: '',
  requestBytes: 0,
  responseBytes: 0,
  durationMs: 0
})

const packetHistory = ref([])

onMounted(() => {
  const saved = localStorage.getItem('ck-packet-v2-prefs')
  if (saved) {
    try {
      Object.assign(packet, JSON.parse(saved))
    } catch (e) {}
  }
  const hist = localStorage.getItem('ck-packet-v2-history')
  if (hist) {
    try {
      packetHistory.value = JSON.parse(hist)
    } catch (e) {}
  }
})

watch(packet, (newVal) => {
  localStorage.setItem('ck-packet-v2-prefs', JSON.stringify(newVal))
}, { deep: true })

async function loadCertFile(field) {
  const path = await SelectFile()
  if (!path) return
  const content = await ReadFile(path)
  if (content) {
    packet[field] = content
    store.showToast('文件加载成功')
  }
}

async function choosePacketFile() {
  const path = await SelectFile()
  if (path) packet.filePath = path
}

async function sendPacketNow() {
  packetResult.error = ''
  packetResult.success = null
  
  const r = await SendPacket({
    host: packet.host,
    port: packet.port,
    network: packet.network,
    transport: packet.transport,
    serverName: packet.serverName,
    insecureSkipVerify: packet.insecureSkipVerify,
    headerLength: packet.headerLength,
    timeoutMs: packet.timeoutMs,
    payloadFormat: packet.payloadFormat,
    payload: packet.payloadData,
    responseFormat: 'hex',
    filePath: packet.filePath,
    caCertPem: packet.caCert,
    clientCertPem: packet.clientCert,
    clientKeyPem: packet.clientKey,
    clientEncCertPem: packet.clientEncCert,
    clientEncKeyPem: packet.clientEncKey,
  })

  packetResult.success = r.success
  packetResult.error = r.error
  packetResult.responseHex = r.responseHex
  packetResult.headerHex = r.headerHex
  packetResult.requestBytes = r.requestBytes
  packetResult.responseBytes = r.responseBytes
  packetResult.durationMs = r.durationMs

  if (r.success) {
    const historyEntry = {
      id: Date.now(),
      time: new Date().toLocaleTimeString(),
      host: packet.host,
      port: packet.port,
      preview: packet.payloadData.substring(0, 32) + (packet.payloadData.length > 32 ? '...' : ''),
      ...packet
    }
    packetHistory.value.unshift(historyEntry)
    packetHistory.value = packetHistory.value.slice(0, 20)
    localStorage.setItem('ck-packet-v2-history', JSON.stringify(packetHistory.value))
  }
}

function applyHistory(h) {
  Object.assign(packet, h)
  store.showToast('已加载历史配置')
}

function resetPacket() {
  packet.payloadData = ''
  packet.filePath = ''
  packetResult.success = null
  packetResult.error = ''
  packetResult.responseHex = ''
  packetResult.headerHex = ''
}

async function copy(t) {
  if (!t) return
  await navigator.clipboard.writeText(t)
  store.showToast('已复制')
}
</script>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 4px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: transparent;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(139, 92, 246, 0.2);
  border-radius: 10px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: rgba(139, 92, 246, 0.4);
}
</style>