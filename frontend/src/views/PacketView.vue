<template>
  <PageLayout title="报文发送 / 接收" subtitle="TCP 报文头长度 · IPv4/IPv6 · TLS/TLCP · 国密双证书 · 发送历史"
              icon-bg="bg-indigo-500/20">
    <template #icon>
      <SendIcon class="w-4 h-4 text-indigo-400" />
    </template>

    <template #actions>
       <div class="flex gap-2">
         <Button variant="tool" size="sm" @click="showHelp = true">
           <InfoIcon class="w-3 h-3" /> 使用说明
         </Button>
         <Button variant="secondary" size="sm" @click="showPrinciple = true">
           <ShieldCheckIcon class="w-3.5 h-3.5" /> 算法原理
         </Button>
       </div>
     </template>

     <!-- Help Modal -->
     <transition name="fade">
       <div v-if="showHelp" class="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" @click.self="showHelp = false">
         <div class="card max-w-lg w-full shadow-2xl animate-in zoom-in-95 duration-200" :class="isDark ? 'bg-dark-card border-dark-border' : 'bg-white border-gray-200'">
           <div class="flex justify-between items-center mb-4 border-b pb-3" :class="isDark ? 'border-dark-border' : 'border-gray-100'">
             <h3 class="text-sm font-bold flex items-center gap-2">
               <InfoIcon class="w-4 h-4 text-violet-400" /> 使用说明
             </h3>
              <button @click="showHelp = false" class="p-1 hover:bg-gray-100 dark:hover:bg-dark-hover rounded-md transition-colors">
               <XIcon class="w-4 h-4 text-dark-muted" />
             </button>
           </div>
           <div class="text-sm leading-relaxed space-y-3" :class="isDark ? 'text-dark-muted' : 'text-gray-600'">
             <p class="font-bold text-violet-400 text-[13px]">使用步骤</p>
             <p class="text-[13px]">1. 配置连接信息：填写主机地址和端口号</p>
             <p class="text-[13px]">2. 选择网络协议：IPv4 或 IPv6</p>
             <p class="text-[13px]">3. 设置安全模式：明文、TLS 或国密 TLCP</p>
             <p class="text-[13px]">4. 配置证书（如果使用安全模式）：上传 CA 证书、客户端证书和私钥</p>
             <p class="text-[13px]">5. 设置报文头长度：选择 0、1、2 或 4 字节</p>
             <p class="text-[13px]">6. 配置超时时间：设置连接和响应的等待时间（毫秒）</p>
             <p class="font-bold text-violet-400 mt-2 text-[13px]">报文发送</p>
             <p class="text-[13px]">• 选择报文格式：HEX 或 文本</p>
             <p class="text-[13px]">• 输入报文内容：直接输入或通过外部文件加载</p>
             <p class="text-[13px]">• 点击发送请求按钮开始传输</p>
             <p class="font-bold text-violet-400 mt-2 text-[13px]">查看结果</p>
             <p class="text-[13px]">• 查看发送和接收的字节数</p>
             <p class="text-[13px]">• 查看报文头内容（如果已配置）</p>
             <p class="text-[13px]">• 查看响应数据：支持复制和错误提示</p>
           </div>
           <div class="mt-6 flex justify-end">
              <button @click="showHelp = false" class="btn-success px-6">确定</button>
           </div>
         </div>
        </div>
      </transition>

    <!-- Algorithm Principle Drawer -->
    <AlgorithmDrawer
      :is-open="showPrinciple"
      :title="currentPrinciple.title"
      :icon="ShieldCheckIcon"
      @close="showPrinciple = false"
    >
      <div v-for="(section, idx) in parsedPrinciples" :key="idx">
        <h4>{{ section.title }}</h4>
        <p v-for="(line, lIdx) in section.content" :key="lIdx" class="principle-line">
          {{ line }}
        </p>
      </div>
    </AlgorithmDrawer>

    <div class="packet-workbench animate-fade-in">
      <!-- Left side: Connection and Security -->
      <div class="packet-side overflow-y-auto pr-1 custom-scrollbar">
        <Card title="连接与协议" class="space-y-3">
          <div class="grid grid-cols-4 gap-2">
            <div class="col-span-3">
              <Input v-model="packet.host" label="主机地址" class="font-mono" placeholder="127.0.0.1" />
            </div>
            <div>
              <Input v-model.number="packet.port" label="端口" type="number" class="font-mono" />
            </div>
          </div>
          <div class="grid grid-cols-4 gap-2">
            <div>
              <label class="input-label">网络</label>
              <Dropdown
                v-model="packet.network"
                :options="[
                  { value: 'auto', label: '自动' },
                  { value: 'tcp4', label: 'IPv4' },
                  { value: 'tcp6', label: 'IPv6' }
                ]"
              />
            </div>
            <div>
              <label class="input-label">安全模式</label>
              <Dropdown
                v-model="packet.transport"
                :options="[
                  { value: 'plain', label: '明文' },
                  { value: 'tls', label: 'TLS' },
                  { value: 'tlcp', label: 'TLCP' }
                ]"
              />
            </div>
            <div>
              <label class="input-label">长度头</label>
              <Dropdown
                v-model="packet.headerLength"
                :options="[
                  { value: '0', label: '无' },
                  { value: '1', label: '1B' },
                  { value: '2', label: '2B' },
                  { value: '4', label: '4B' }
                ]"
              />
            </div>
            <div>
              <Input v-model.number="packet.timeoutMs" label="超时(ms)" type="number" />
            </div>
          </div>
        </Card>

        <!-- TLS/TLCP Certs - Conditional -->
        <div v-if="packet.transport !== 'plain'" class="card space-y-2 animate-in fade-in duration-300">
          <p class="card-title">安全证书 ({{ packet.transport.toUpperCase() }})</p>
          <div class="space-y-2">
            <div class="space-y-1">
              <div class="flex justify-between items-center">
                <label class="input-label !mb-0">CA 根证书</label>
                <Button variant="tool" size="xs" @click="loadCertFile('caCert')"><UploadIcon class="w-2.5 h-2.5" /> 上传</Button>
              </div>
              <div class="relative">
                <textarea v-model="packet.caCert" rows="1" class="input !min-h-0 py-1 pb-7 font-mono" placeholder="PEM..."></textarea>
                <ByteBadge :model-value="packet.caCert" />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-2">
              <div class="space-y-1">
                <div class="flex justify-between items-center">
                  <label class="input-label !mb-0">签名证书</label>
                  <Button variant="tool" size="xs" @click="loadCertFile('clientCert')"><UploadIcon class="w-2.5 h-2.5" /> 上传</Button>
                </div>
                <div class="relative">
                  <textarea v-model="packet.clientCert" rows="1" class="input !min-h-0 py-1 pb-7 font-mono"></textarea>
                  <ByteBadge :model-value="packet.clientCert" />
                </div>
              </div>
              <div class="space-y-1">
                <div class="flex justify-between items-center">
                  <label class="input-label !mb-0">签名私钥</label>
                  <Button variant="tool" size="xs" @click="loadCertFile('clientKey')"><UploadIcon class="w-2.5 h-2.5" /> 上传</Button>
                </div>
                <div class="relative">
                  <textarea v-model="packet.clientKey" rows="1" class="input !min-h-0 py-1 pb-7 font-mono"></textarea>
                  <ByteBadge :model-value="packet.clientKey" />
                </div>
              </div>
            </div>
            <div v-if="packet.transport === 'tlcp'" class="grid grid-cols-2 gap-2 animate-in slide-in-from-top-1 duration-200">
              <div class="space-y-1">
                <div class="flex justify-between items-center">
                  <label class="input-label !mb-0">加密证书</label>
                  <Button variant="tool" size="xs" @click="loadCertFile('clientEncCert')"><UploadIcon class="w-2.5 h-2.5" /> 上传</Button>
                </div>
                <div class="relative">
                  <textarea v-model="packet.clientEncCert" rows="1" class="input !min-h-0 py-1 pb-7 font-mono"></textarea>
                  <ByteBadge :model-value="packet.clientEncCert" />
                </div>
              </div>
              <div class="space-y-1">
                <div class="flex justify-between items-center">
                  <label class="input-label !mb-0">加密私钥</label>
                  <Button variant="tool" size="xs" @click="loadCertFile('clientEncKey')"><UploadIcon class="w-2.5 h-2.5" /> 上传</Button>
                </div>
                <div class="relative">
                  <textarea v-model="packet.clientEncKey" rows="1" class="input !min-h-0 py-1 pb-7 font-mono"></textarea>
                  <ByteBadge :model-value="packet.clientEncKey" />
                </div>
              </div>
            </div>
            <label class="flex items-center gap-2 cursor-pointer pt-1">
              <input type="checkbox" v-model="packet.insecureSkipVerify" class="rounded border-dark-border bg-dark-bg text-violet-500" />
              <span class="text-xs opacity-70">跳过服务端证书校验</span>
            </label>
          </div>
        </div>

        <Card title="历史记录 (最近 20 条)" class="overflow-hidden flex flex-col max-h-[120px]">
          <div v-if="!packetHistory.length" class="flex-1 flex items-center justify-center text-xs opacity-30 italic py-2">无记录</div>
          <div v-else class="flex-1 overflow-y-auto space-y-1 pr-1 custom-scrollbar">
            <button v-for="h in packetHistory" :key="h.id" @click="applyHistory(h)"
                    class="w-full text-left p-1.5 rounded-lg hover:bg-white/5 transition-all border border-transparent hover:border-dark-border flex flex-col gap-0.5 group">
              <div class="flex justify-between items-center">
                <span class="text-xs font-bold text-violet-400">{{ h.host }}:{{ h.port }}</span>
                <span class="text-[10px] opacity-40 group-hover:opacity-100 transition-opacity">{{ h.time }}</span>
              </div>
              <div class="text-[10px] truncate opacity-50 font-mono group-hover:opacity-80 transition-opacity">{{ h.preview }}</div>
            </button>
          </div>
        </Card>
      </div>

      <!-- Right side: Data and Results -->
      <div class="packet-side h-full flex flex-col">
        <Card title="报文发送 (Payload)" class="space-y-2 flex flex-col flex-1 min-h-0">
          <div class="flex items-center justify-between shrink-0">
            <div class="flex gap-2">
              <Button variant="tool" size="sm" @click="choosePacketFile">
                <FolderOpenIcon class="w-3 h-3" /> {{ packet.filePath ? '已选文件' : '外部文件' }}
              </Button>
              <Dropdown
                v-model="packet.payloadFormat"
                :options="[
                  { value: 'hex', label: 'HEX' },
                  { value: 'text', label: 'TEXT' }
                ]"
              />
            </div>
          </div>
          
          <div v-if="packet.filePath" class="px-2 py-1 rounded-lg bg-violet-500/10 border border-violet-500/20 text-xs flex items-center justify-between shrink-0 animate-in fade-in zoom-in-95">
            <span class="truncate font-mono opacity-80">{{ packet.filePath }}</span>
            <button @click="packet.filePath = ''" class="text-violet-400 hover:text-violet-300 px-1">✕</button>
          </div>
          
          <div class="flex-1 min-h-0">
            <textarea v-model="packet.payloadData" class="input h-full font-mono text-xs leading-relaxed" 
                      :placeholder="packet.payloadFormat === 'hex' ? '输入 16 进制报文...' : '输入原始文本内容...'"></textarea>
          </div>

          <div class="flex gap-2 shrink-0 pt-2 border-t border-dark-border/30">
            <Button variant="success" class="flex-1 justify-center" @click="sendPacketNow">
              <ZapIcon class="w-3.5 h-3.5" /> 发送请求
            </Button>
            <Button variant="secondary" class="px-3" title="重置内容" @click="resetPacket"><RefreshCwIcon class="w-3.5 h-3.5" /></Button>
          </div>
        </Card>

        <Card title="响应数据 (Response)" class="space-y-2 shrink-0">
          <div class="flex items-center justify-between">
            <div class="flex gap-3 text-xs opacity-60 font-mono">
              <span v-if="packetResult.requestBytes" class="text-cyan-400">已发: {{ packetResult.requestBytes }}B</span>
              <span v-if="packetResult.responseBytes" class="text-emerald-400">已收: {{ packetResult.responseBytes }}B</span>
              <span v-if="packetResult.durationMs" class="text-orange-300">{{ packetResult.durationMs }}ms</span>
            </div>
          </div>
          <div class="space-y-2">
            <div v-if="packetResult.headerHex" class="space-y-1">
              <label class="text-[10px] opacity-50 uppercase tracking-widest font-bold">报文头 ({{ packet.headerLength }}B)</label>
              <div class="relative">
                <div class="result-area !min-h-0 py-1.5 pb-7 font-mono text-xs break-all bg-dark-bg/30">{{ packetResult.headerHex }}</div>
                <ByteBadge :model-value="packetResult.headerHex" />
              </div>
            </div>
            <div class="space-y-1">
              <div class="flex justify-between items-center">
                <label class="text-[10px] opacity-50 uppercase tracking-widest font-bold">响应内容</label>
                <Button variant="tool" size="xs" v-if="packetResult.responseHex" @click="copy(packetResult.responseHex)"><CopyIcon class="w-3 h-3" /></Button>
              </div>
              <div class="relative">
                <div class="result-area !min-h-[60px] pb-7 font-mono text-xs break-all max-h-[100px] overflow-y-auto leading-relaxed" 
                     :class="{ 'text-red-400 border-red-500/20 bg-red-500/5': packetResult.error, 'text-emerald-400/90': !packetResult.error && packetResult.responseHex }">
                  {{ packetResult.error || packetResult.responseHex || '等待网络响应...' }}
                </div>
                <ByteBadge v-if="packetResult.responseHex" :model-value="packetResult.responseHex" />
              </div>
            </div>
          </div>
        </Card>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { SendIcon, ZapIcon, RefreshCwIcon, FolderOpenIcon, UploadIcon, CopyIcon, InfoIcon, XIcon, ShieldCheckIcon } from '@lucide/vue'
import Card from '../components/Card.vue'
import Input from '../components/Input.vue'
import Button from '../components/Button.vue'
import ResultArea from '../components/ResultArea.vue'
import AlgorithmDrawer from '../components/AlgorithmDrawer.vue'
import Dropdown from '../components/Dropdown.vue'
import PageLayout from '../components/PageLayout.vue'
import ByteBadge from '../components/ByteBadge.vue'
import { SelectFile, ReadFile, SendPacket } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const showPrinciple = ref(false)
const showHelp = ref(false)

// Principle content for algorithm drawer
const principleData = ref({
  title: '报文发送原理',
  content: `TCP 明文传输:
TCP (Transmission Control Protocol) 提供可靠的、面向连接的字节流服务。数据以明文形式在网络中传输，不提供任何加密保护。
• 三次握手: 建立可靠连接，确保双方都能收发数据。
• 流量控制: 通过滑动窗口机制防止接收方缓冲区溢出。
• 适用场景: 内网环境、对安全性要求不高的调试场景。

TLS 安全传输:
TLS (Transport Layer Security) 是广泛使用的传输层安全协议，保护数据在传输过程中的机密性和完整性。
• 握手过程: 协商加密套件、验证证书、交换会话密钥。
• 加密算法: 支持 AES-GCM、ChaCha20-Poly1305 等现代加密算法。
• 证书验证: 通过 CA 证书链验证服务器身份，防止中间人攻击。
• 应用场景: HTTPS、邮件传输、API 通信等。

TLCP 国密传输:
TLCP (Transport Layer Cryptography Protocol) 是国密标准的传输层安全协议，使用国密算法体系满足国内合规要求。
• 双证书体系: 使用签名证书+加密证书，分别用于身份认证和数据加密。
• 国密算法: SM2 密钥交换、SM3 哈希、SM4 对称加密。
• 双向认证: 支持客户端证书认证，实现更强的身份验证。
• 合规要求: 满足国内金融、政务等行业的安全合规要求。`
})

const currentPrinciple = computed(() => principleData.value)

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
  network: 'auto',
  transport: 'plain',
  serverName: '',
  insecureSkipVerify: false,
  caCert: '',
  clientCert: '',
  clientKey: '',
  clientEncCert: '',
  clientEncKey: '',
  headerLength: '4',
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
    headerLength: parseInt(packet.headerLength),
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
    const histEntry = {
      id: Date.now(),
      host: packet.host,
      port: packet.port,
      time: new Date().toLocaleTimeString(),
      preview: packet.payloadData.slice(0, 50) + (packet.payloadData.length > 50 ? '...' : '')
    }
    packetHistory.value = [histEntry, ...packetHistory.value.slice(0, 19)]
    localStorage.setItem('ck-packet-v2-history', JSON.stringify(packetHistory.value))
  }
}

function applyHistory(h) {
  packet.host = h.host
  packet.port = h.port
}

function resetPacket() {
  packet.payloadData = ''
  packet.filePath = ''
  packetResult.success = null
  packetResult.error = ''
  packetResult.responseHex = ''
  packetResult.headerHex = ''
  packetResult.requestBytes = 0
  packetResult.responseBytes = 0
  packetResult.durationMs = 0
}

function copy(text) {
  navigator.clipboard.writeText(text)
  store.showToast('已复制到剪贴板')
}
</script>

<style scoped>
.packet-workbench {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  height: 100%;
}

.packet-side {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

/* 自定义滚动条 */
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

.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: var(--muted);
}

.payload-format-select {
  height: 100%;
  line-height: 1;
}
</style>
