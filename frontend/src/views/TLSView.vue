<template>
  <PageLayout title="TLS / TLCP 连接测试" subtitle="TLS 1.0-1.3 · 国密 TLCP 1.1 · PQC 混合 · 自测模式"
              icon-bg="bg-sky-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <ShieldCheckIcon class="w-4 h-4 text-sky-400" />
    </template>

    <!-- TLS/TLCP 连接测试 -->
    <div v-if="activeTab === 'connect'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <!-- 连接参数 -->
        <Card>
          <div class="flex items-center gap-2 mb-3">
            <span class="badge bg-sky-500/20 text-sky-400">连接</span>
            <p class="text-sm font-medium">服务器地址</p>
          </div>
          <div class="grid grid-cols-3 gap-2 mb-3">
            <div class="col-span-2">
              <label class="input-label">主机名 / IP</label>
              <Input v-model="form.host" placeholder="example.com" />
            </div>
            <div>
              <label class="input-label">端口</label>
              <Input v-model.number="form.port" placeholder="443" />
            </div>
          </div>
          <div class="mb-3">
            <label class="input-label">协议</label>
            <Dropdown
              v-model="form.protocol"
              :options="[
                { value: 'tls1.2', label: 'TLS 1.2' },
                { value: 'tls1.3', label: 'TLS 1.3' },
                { value: 'tlcp', label: 'TLCP 1.1 (国密)' },
                { value: 'tls1.0', label: 'TLS 1.0 (兼容)' },
                { value: 'tls1.1', label: 'TLS 1.1 (兼容)' },
              ]"
            />
          </div>
          <div class="mb-3">
            <label class="input-label">Server Name (SNI)</label>
            <Input v-model="form.serverName" placeholder="留空则使用主机名" />
          </div>
          <div class="flex items-center gap-4 mb-3">
            <label class="flex items-center gap-2">
              <input type="checkbox" v-model="form.insecureSkipVerify" class="rounded" />
              <span class="text-xs">跳过证书验证</span>
            </label>
            <label class="flex items-center gap-2">
              <input type="checkbox" v-model="form.enablePQC" class="rounded" />
              <span class="text-xs text-violet-400">启用 PQC 混合</span>
            </label>
          </div>
          <Button variant="success" block @click="doConnect" :disabled="connecting">
            <LockIcon class="w-3.5 h-3.5" />
            {{ connecting ? '连接中...' : '建立连接' }}
          </Button>
        </Card>

        <!-- 证书配置 -->
        <Card title="客户端证书 (可选)">
          <div class="space-y-2">
            <div>
              <label class="input-label">CA 证书 (PEM)</label>
              <div class="flex gap-1">
                <div class="relative flex-1">
                  <textarea v-model="form.caCertPEM" rows="2" class="ck-textarea w-full !pb-7" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                  <ByteBadge :model-value="form.caCertPEM" />
                </div>
                <Button variant="tool" size="sm" @click="loadFile('caCertPEM')"><FolderOpenIcon class="w-3 h-3" /></Button>
              </div>
            </div>
            <div>
              <label class="input-label">签名证书 (PEM)</label>
              <div class="flex gap-1">
                <div class="relative flex-1">
                  <textarea v-model="form.clientCertPEM" rows="2" class="ck-textarea w-full !pb-7" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                  <ByteBadge :model-value="form.clientCertPEM" />
                </div>
                <Button variant="tool" size="sm" @click="loadFile('clientCertPEM')"><FolderOpenIcon class="w-3 h-3" /></Button>
              </div>
            </div>
            <div>
              <label class="input-label">签名私钥 (PEM)</label>
              <div class="flex gap-1">
                <div class="relative flex-1">
                  <textarea v-model="form.clientKeyPEM" rows="2" class="ck-textarea w-full !pb-7" placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
                  <ByteBadge :model-value="form.clientKeyPEM" />
                </div>
                <Button variant="tool" size="sm" @click="loadFile('clientKeyPEM')"><FolderOpenIcon class="w-3 h-3" /></Button>
              </div>
            </div>
            <template v-if="form.protocol === 'tlcp'">
              <div>
                <label class="input-label text-violet-400">加密证书 (PEM) — TLCP</label>
                <div class="flex gap-1">
                  <div class="relative flex-1">
                    <textarea v-model="form.clientEncCertPEM" rows="2" class="ck-textarea w-full !pb-7"></textarea>
                    <ByteBadge :model-value="form.clientEncCertPEM" />
                  </div>
                  <Button variant="tool" size="sm" @click="loadFile('clientEncCertPEM')"><FolderOpenIcon class="w-3 h-3" /></Button>
                </div>
              </div>
              <div>
                <label class="input-label text-violet-400">加密私钥 (PEM) — TLCP</label>
                <div class="flex gap-1">
                  <div class="relative flex-1">
                    <textarea v-model="form.clientEncKeyPEM" rows="2" class="ck-textarea w-full !pb-7"></textarea>
                    <ByteBadge :model-value="form.clientEncKeyPEM" />
                  </div>
                  <Button variant="tool" size="sm" @click="loadFile('clientEncKeyPEM')"><FolderOpenIcon class="w-3 h-3" /></Button>
                </div>
              </div>
            </template>
          </div>
        </Card>
      </div>

      <!-- 连接结果 -->
      <div class="space-y-3">
        <Card>
          <div class="flex items-center gap-2 mb-3">
            <span class="badge" :class="connResult.success ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'">
              {{ connResult.success ? '已连接' : '未连接' }}
            </span>
            <p class="text-sm font-medium">连接结果</p>
          </div>

          <div v-if="connResult.error" class="p-3 rounded-xl border border-red-500/20 bg-red-500/5 text-red-400 text-xs mb-3">
            {{ connResult.error }}
          </div>

          <div v-if="connResult.success" class="space-y-3">
            <div class="grid grid-cols-2 gap-2">
              <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <p class="text-[10px] text-muted mb-0.5">协议版本</p>
                <p class="text-sm font-semibold" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ connResult.tlsVersion }}</p>
              </div>
              <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <p class="text-[10px] text-muted mb-0.5">握手耗时</p>
                <p class="text-sm font-semibold" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ connResult.handshakeTimeMs }} ms</p>
              </div>
              <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <p class="text-[10px] text-muted mb-0.5">密码套件</p>
                <p class="text-xs font-semibold break-all" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ connResult.cipherSuite }}</p>
              </div>
              <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <p class="text-[10px] text-muted mb-0.5">套件 ID</p>
                <p class="text-sm font-mono font-semibold" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ connResult.cipherSuiteId }}</p>
              </div>
            </div>

            <div v-if="connResult.curveUsed && connResult.curveUsed !== 'N/A'" class="flex items-center gap-2 text-xs">
              <span class="text-muted">密钥交换:</span>
              <span class="font-mono" :class="connResult.curveUsed.includes('PQC') ? 'text-violet-400' : (isDark ? 'text-dark-text' : 'text-light-text')">
                {{ connResult.curveUsed }}
              </span>
            </div>
            <div v-if="connResult.serverName" class="flex items-center gap-2 text-xs">
              <span class="text-muted">SNI:</span>
              <span class="font-mono" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ connResult.serverName }}</span>
            </div>
            <div v-if="connResult.alpnProtocol" class="flex items-center gap-2 text-xs">
              <span class="text-muted">ALPN:</span>
              <span class="font-mono" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ connResult.alpnProtocol }}</span>
            </div>
          </div>
        </Card>

        <!-- 证书信息 -->
        <Card v-if="connResult.peerCertificates && connResult.peerCertificates.length > 0">
          <div class="flex items-center gap-2 mb-3">
            <span class="badge bg-violet-500/20 text-violet-400">证书</span>
            <p class="text-sm font-medium">服务器证书链 ({{ connResult.peerCertificates.length }})</p>
          </div>
          <div class="space-y-3">
            <div v-for="(cert, idx) in connResult.peerCertificates" :key="idx"
                 class="p-3 rounded-xl border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
              <div class="flex items-center gap-2 mb-2">
                <span class="text-xs font-bold px-2 py-0.5 rounded" :class="cert.isCA ? 'bg-amber-500/20 text-amber-400' : 'bg-emerald-500/20 text-emerald-400'">
                  {{ cert.isCA ? 'CA' : (idx === 0 ? 'Leaf' : 'Intermediate') }}
                </span>
              </div>
              <div class="space-y-1 text-[11px]">
                <p><span class="text-muted w-16 inline-block">Subject:</span> <span class="font-mono break-all">{{ cert.subject }}</span></p>
                <p><span class="text-muted w-16 inline-block">Issuer:</span> <span class="font-mono break-all">{{ cert.issuer }}</span></p>
                <p><span class="text-muted w-16 inline-block">有效期:</span> {{ cert.notBefore }} ~ {{ cert.notAfter }}</p>
                <p><span class="text-muted w-16 inline-block">算法:</span> {{ cert.keyAlgorithm }} / {{ cert.sigAlgorithm }}</p>
                <div class="mt-1">
                  <p class="text-muted mb-0.5">指纹:</p>
                  <p class="font-mono text-[10px] break-all bg-black/5 dark:bg-white/5 p-1.5 rounded">{{ cert.fingerprint }}</p>
                </div>
              </div>
            </div>
          </div>
        </Card>
      </div>
    </div>

    <!-- 自测模式：本地服务端 + 客户端双向演示 -->
    <div v-if="activeTab === 'selftest'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <!-- 左侧：服务端 -->
      <div class="space-y-3">
        <Card>
          <div class="flex items-center gap-2 mb-3">
            <span class="badge bg-emerald-500/20 text-emerald-400">服务端</span>
            <p class="text-sm font-medium">本地 TLS/TLCP 服务端</p>
          </div>
          <div class="flex items-end gap-2 mb-3">
            <div class="flex-1">
              <label class="input-label">协议</label>
              <Dropdown
                v-model="selfTest.protocol"
                :options="[
                  { value: 'tls1.2', label: 'TLS 1.2' },
                  { value: 'tls1.3', label: 'TLS 1.3' },
                  { value: 'tlcp', label: 'TLCP 1.1 (国密 SM2+SM4)' },
                ]"
              />
            </div>
            <label class="flex items-center gap-2 pb-2 shrink-0">
              <input type="checkbox" :checked="selfTest.enablePQC" @change="selfTest.enablePQC = $event.target.checked" class="rounded" />
              <span class="text-xs text-violet-400">PQC 混合</span>
            </label>
          </div>
          <div class="flex gap-2 mb-3">
            <Button variant="success" class="flex-1 justify-center" @click="startDemoServer" :disabled="demoServerStarting">
              <ServerIcon class="w-3.5 h-3.5" />
              {{ demoServerStarting ? '启动中...' : (demo.serverStatus === 'listening' || demo.serverStatus === 'connected' ? '重启服务端' : '启动服务端') }}
            </Button>
            <Button variant="danger" class="shrink-0" @click="stopDemo" :disabled="!demo.sessionId" title="停止并关闭">
              <XIcon class="w-3.5 h-3.5" />
            </Button>
          </div>
          <div class="flex items-center gap-2 text-xs mb-1">
            <span class="text-muted">监听地址:</span>
            <span class="font-mono">{{ demo.port ? '127.0.0.1:' + demo.port : '未启动' }}</span>
            <span class="badge" :class="serverStatusClass">{{ serverStatusText }}</span>
          </div>
          <p v-if="demo.certificate" class="text-[11px] text-muted">{{ demo.certificate }}</p>
        </Card>

        <!-- 服务端协商流程 -->
        <Card v-if="demo.serverTimeline.length" title="服务端协商流程">
          <div class="space-y-1.5">
            <div v-for="(line, i) in demo.serverTimeline" :key="i"
                 class="flex items-start gap-2 text-[11px]"
                 :class="line.startsWith('✓') ? 'text-emerald-400 font-semibold' : (line.startsWith('✗') ? 'text-red-400' : 'text-muted')">
              <span class="shrink-0 w-4 text-center text-[9px] mt-0.5 opacity-60">{{ i + 1 }}</span>
              <span class="font-mono break-all">{{ line }}</span>
            </div>
          </div>
        </Card>

        <!-- 服务端消息 -->
        <Card title="服务端消息">
          <div class="mb-2 flex gap-2">
            <Input v-model="demoServerMsg" placeholder="服务端发送的消息..." @keyup.enter="sendDemo('server')" />
            <Button variant="success" class="shrink-0" @click="sendDemo('server')">发送</Button>
          </div>
          <div v-if="!demo.serverMessages.length" class="text-xs text-muted py-2">等待客户端发来消息...</div>
          <div v-else class="space-y-1 max-h-48 overflow-y-auto">
            <div v-for="(m, i) in demo.serverMessages" :key="i"
                 class="text-[11px] font-mono p-1.5 rounded-lg" :class="isDark ? 'bg-dark-bg' : 'bg-slate-50'">
              <span class="text-emerald-400 mr-1">客户端 →</span> {{ m }}
            </div>
          </div>
        </Card>
      </div>

      <!-- 右侧：客户端 -->
      <div class="space-y-3">
        <Card>
          <div class="flex items-center gap-2 mb-3">
            <span class="badge bg-sky-500/20 text-sky-400">客户端</span>
            <p class="text-sm font-medium">连接本地服务端</p>
          </div>
          <Button variant="secondary" block @click="connectDemoClient"
                  :disabled="!demo.sessionId || demoClientConnecting || demo.clientStatus === 'connected'">
            <LinkIcon class="w-3.5 h-3.5" />
            {{ demoClientConnecting ? '连接中...' : (demo.clientStatus === 'connected' ? '已连接' : '连接本地服务端') }}
          </Button>
          <div class="flex items-center gap-2 text-xs mt-3">
            <span class="text-muted">连接地址:</span>
            <span class="font-mono">{{ demo.port ? '127.0.0.1:' + demo.port : '请先启动服务端' }}</span>
            <span class="badge" :class="clientStatusClass">{{ clientStatusText }}</span>
          </div>
        </Card>

        <!-- 客户端协商流程 -->
        <Card v-if="demo.clientTimeline.length" title="客户端协商流程">
          <div class="space-y-1.5">
            <div v-for="(line, i) in demo.clientTimeline" :key="i"
                 class="flex items-start gap-2 text-[11px]"
                 :class="line.startsWith('✓') ? 'text-emerald-400 font-semibold' : (line.startsWith('✗') ? 'text-red-400' : 'text-muted')">
              <span class="shrink-0 w-4 text-center text-[9px] mt-0.5 opacity-60">{{ i + 1 }}</span>
              <span class="font-mono break-all">{{ line }}</span>
            </div>
          </div>
        </Card>

        <!-- 客户端消息 -->
        <Card title="客户端消息">
          <div class="mb-2 flex gap-2">
            <Input v-model="demoClientMsg" placeholder="客户端发送的消息..." @keyup.enter="sendDemo('client')" />
            <Button variant="success" class="shrink-0" @click="sendDemo('client')">发送</Button>
          </div>
          <div v-if="!demo.clientMessages.length" class="text-xs text-muted py-2">等待服务端发来消息...</div>
          <div v-else class="space-y-1 max-h-48 overflow-y-auto">
            <div v-for="(m, i) in demo.clientMessages" :key="i"
                 class="text-[11px] font-mono p-1.5 rounded-lg" :class="isDark ? 'bg-dark-bg' : 'bg-slate-50'">
              <span class="text-sky-400 mr-1">服务端 →</span> {{ m }}
            </div>
          </div>
        </Card>

        <!-- 协商结果 -->
        <Card v-if="demo.tlsVersion" title="协商结果">
          <div class="grid grid-cols-2 gap-2">
            <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
              <p class="text-[10px] text-muted mb-0.5">协议版本</p>
              <p class="text-sm font-semibold">{{ demo.tlsVersion }}</p>
            </div>
            <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
              <p class="text-[10px] text-muted mb-0.5">密钥交换</p>
              <p class="text-xs font-semibold break-all" :class="demo.curveUsed?.includes('PQC') ? 'text-violet-400' : ''">{{ demo.curveUsed }}</p>
            </div>
            <div class="col-span-2 p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
              <p class="text-[10px] text-muted mb-0.5">密码套件</p>
              <p class="text-xs font-semibold break-all">{{ demo.cipherSuite }}</p>
            </div>
          </div>
        </Card>
      </div>
    </div>

    <!-- 密码套件参考 (连接测试页面底部) -->
    <div v-if="activeTab === 'connect'" class="mt-4">
      <button @click="showSuites = !showSuites" class="flex items-center gap-2 text-xs font-semibold text-muted hover:text-text transition-colors">
        <ChevronDownIcon class="w-3.5 h-3.5 transition-transform" :class="{ '-rotate-90': !showSuites }" />
        密码套件参考
      </button>
      <div v-if="showSuites" class="grid grid-cols-2 gap-4 mt-3 animate-fade-in">
        <Card title="TLS 密码套件">
          <div class="space-y-1 text-xs">
            <div v-for="s in tlsCipherSuites" :key="s" class="p-1.5 rounded-lg hover:bg-black/5 dark:hover:bg-white/5 font-mono">
              {{ s }}
            </div>
          </div>
        </Card>
        <Card title="TLCP 密码套件 (国密)">
          <div class="space-y-1 text-xs">
            <div v-for="s in tlcpCipherSuites" :key="s" class="p-1.5 rounded-lg hover:bg-black/5 dark:hover:bg-white/5 font-mono">
              {{ s }}
            </div>
          </div>
        </Card>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import { storeToRefs } from 'pinia'
import { ShieldCheckIcon, LockIcon, FolderOpenIcon, ServerIcon, LinkIcon, XIcon, ChevronDownIcon } from '@lucide/vue'
import Card from '../components/Card.vue'
import Input from '../components/Input.vue'
import Button from '../components/Button.vue'
import PageLayout from '../components/PageLayout.vue'
import Dropdown from '../components/Dropdown.vue'
import ByteBadge from '../components/ByteBadge.vue'
import { TLSConnect, TLSDemoServerStart, TLSDemoClientConnect, TLSDemoSend, TLSDemoGetState, TLSDemoClose, ListTLSCipherSuites, ListTLCPCipherSuites, SelectFile, ReadFile } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'connect', label: '连接测试' },
  { id: 'selftest', label: '自测模式' },
]
const activeTab = ref('connect')
const showSuites = ref(false)

// Connect form
const form = reactive({
  host: '',
  port: 443,
  protocol: 'tls1.2',
  serverName: '',
  insecureSkipVerify: true,
  enablePQC: false,
  caCertPEM: '',
  clientCertPEM: '',
  clientKeyPEM: '',
  clientEncCertPEM: '',
  clientEncKeyPEM: '',
})

const connecting = ref(false)
const connResult = reactive({
  success: false,
  protocol: '',
  cipherSuite: '',
  cipherSuiteId: '',
  serverName: '',
  tlsVersion: '',
  handshakeTimeMs: 0,
  peerCertificates: [],
  alpnProtocol: '',
  sessionReused: false,
  curveUsed: '',
  error: '',
})

// Self-test
const selfTest = reactive({
  protocol: 'tls1.3',
  enablePQC: false,
})

// 双向连接演示状态（左侧服务端 / 右侧客户端）
const demo = reactive({
  sessionId: '',
  port: 0,
  serverStatus: 'idle', // idle | listening | connected | error
  clientStatus: 'idle',
  serverTimeline: [],
  clientTimeline: [],
  serverMessages: [],
  clientMessages: [],
  cipherSuite: '',
  tlsVersion: '',
  curveUsed: '',
  certificate: '',
})
const demoServerStarting = ref(false)
const demoClientConnecting = ref(false)
const demoServerMsg = ref('')
const demoClientMsg = ref('')
let demoPollTimer = null

const serverStatusText = computed(() => ({ idle: '未启动', listening: '监听中', connected: '已连接', error: '错误' }[demo.serverStatus] || demo.serverStatus))
const clientStatusText = computed(() => ({ idle: '未连接', connected: '已连接', error: '错误' }[demo.clientStatus] || demo.clientStatus))
const serverStatusClass = computed(() => ({ idle: 'bg-gray-500/20 text-gray-400', listening: 'bg-sky-500/20 text-sky-400', connected: 'bg-emerald-500/20 text-emerald-400', error: 'bg-red-500/20 text-red-400' }[demo.serverStatus] || 'bg-gray-500/20 text-gray-400'))
const clientStatusClass = computed(() => ({ idle: 'bg-gray-500/20 text-gray-400', connected: 'bg-emerald-500/20 text-emerald-400', error: 'bg-red-500/20 text-red-400' }[demo.clientStatus] || 'bg-gray-500/20 text-gray-400'))

function applyDemoState(r) {
  demo.sessionId = r.sessionId || demo.sessionId
  demo.port = r.port ?? demo.port
  if (r.serverStatus) demo.serverStatus = r.serverStatus
  if (r.clientStatus) demo.clientStatus = r.clientStatus
  if (r.serverTimeline) demo.serverTimeline = r.serverTimeline
  if (r.clientTimeline) demo.clientTimeline = r.clientTimeline
  if (r.serverMessages) demo.serverMessages = r.serverMessages
  if (r.clientMessages) demo.clientMessages = r.clientMessages
  if (r.cipherSuite) demo.cipherSuite = r.cipherSuite
  if (r.tlsVersion) demo.tlsVersion = r.tlsVersion
  if (r.curveUsed) demo.curveUsed = r.curveUsed
  if (r.certificate) demo.certificate = r.certificate
}

async function startDemoServer() {
  demoServerStarting.value = true
  try {
    const r = await TLSDemoServerStart({ protocol: selfTest.protocol, enablePQC: selfTest.enablePQC })
    if (r.error && !r.sessionId) {
      // 会话未建立时的错误直接反馈到状态
    }
    applyDemoState(r)
    startDemoPoll()
  } catch (e) {
    demo.serverStatus = 'error'
  } finally {
    demoServerStarting.value = false
  }
}

async function connectDemoClient() {
  if (!demo.sessionId) return
  demoClientConnecting.value = true
  try {
    const r = await TLSDemoClientConnect({ sessionId: demo.sessionId })
    applyDemoState(r)
  } finally {
    demoClientConnecting.value = false
  }
}

async function sendDemo(side) {
  if (!demo.sessionId) return
  const msg = side === 'server' ? demoServerMsg.value : demoClientMsg.value
  if (!msg.trim()) return
  try {
    const r = await TLSDemoSend({ sessionId: demo.sessionId, side, message: msg })
    applyDemoState(r)
    if (side === 'server') demoServerMsg.value = ''
    else demoClientMsg.value = ''
  } catch (e) { /* ignore */ }
}

async function refreshDemo() {
  if (!demo.sessionId) return
  const r = await TLSDemoGetState({ sessionId: demo.sessionId })
  applyDemoState(r)
  if (r.serverStatus === 'idle' && r.clientStatus === 'idle') stopDemoPoll()
}

async function stopDemo() {
  if (demo.sessionId) {
    try { await TLSDemoClose({ sessionId: demo.sessionId }) } catch (e) { /* ignore */ }
  }
  stopDemoPoll()
  Object.assign(demo, {
    sessionId: '', port: 0, serverStatus: 'idle', clientStatus: 'idle',
    serverTimeline: [], clientTimeline: [], serverMessages: [], clientMessages: [],
    cipherSuite: '', tlsVersion: '', curveUsed: '', certificate: '',
  })
}

function startDemoPoll() {
  if (demoPollTimer) return
  demoPollTimer = setInterval(refreshDemo, 1000)
}
function stopDemoPoll() {
  if (demoPollTimer) { clearInterval(demoPollTimer); demoPollTimer = null }
}
onUnmounted(stopDemoPoll)

const tlsCipherSuites = ref([])
const tlcpCipherSuites = ref([])

async function doConnect() {
  if (!form.host) return
  connecting.value = true
  connResult.success = false
  connResult.error = ''
  connResult.peerCertificates = []

  try {
    const r = await TLSConnect({
      host: form.host,
      port: form.port || 443,
      protocol: form.protocol,
      serverName: form.serverName,
      insecureSkipVerify: form.insecureSkipVerify,
      enablePQC: form.enablePQC,
      caCertPEM: form.caCertPEM,
      clientCertPEM: form.clientCertPEM,
      clientKeyPEM: form.clientKeyPEM,
      clientEncCertPEM: form.clientEncCertPEM,
      clientEncKeyPEM: form.clientEncKeyPEM,
      timeoutMs: 10000,
    })
    Object.assign(connResult, r)
  } catch (e) {
    connResult.error = String(e)
  } finally {
    connecting.value = false
  }
}

async function loadFile(field) {
  const path = await SelectFile()
  if (!path) return
  const content = await ReadFile(path)
  if (content) {
    form[field] = content
  }
}

onMounted(async () => {
  try {
    const [tls, tlcp] = await Promise.all([ListTLSCipherSuites(), ListTLCPCipherSuites()])
    if (tls.success) tlsCipherSuites.value = tls.data.split('\n')
    if (tlcp.success) tlcpCipherSuites.value = tlcp.data.split('\n')
  } catch {}
})
</script>

<style scoped>
.text-muted {
  color: var(--muted);
}
</style>
