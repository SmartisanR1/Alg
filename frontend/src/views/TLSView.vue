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

    <!-- 自测模式 -->
    <div v-if="activeTab === 'selftest'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <Card>
          <div class="flex items-center gap-2 mb-3">
            <span class="badge bg-emerald-500/20 text-emerald-400">自测</span>
            <p class="text-sm font-medium">本地 Server + Client</p>
          </div>
          <p class="text-xs mb-3" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            自动创建本地 TLS/TLCP 服务端和客户端，自发送自接收，验证协议握手和数据传输。
          </p>
          <div class="mb-3">
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
          <div class="mb-3">
            <label class="input-label">测试消息</label>
            <Input v-model="selfTest.message" placeholder="Hello from CryptoKit!" />
          </div>
          <div class="flex items-center gap-2 mb-3">
            <label class="flex items-center gap-2">
              <input type="checkbox" :checked="selfTest.enablePQC" @change="selfTest.enablePQC = $event.target.checked" class="rounded" />
              <span class="text-xs text-violet-400">启用 PQC 混合密钥交换 (X25519MLKEM768)</span>
            </label>
          </div>
          <Button variant="success" block @click="doSelfTest" :disabled="selfTesting">
            <ZapIcon class="w-3.5 h-3.5" />
            {{ selfTesting ? '测试中...' : '执行自测' }}
          </Button>
        </Card>

        <!-- 原理说明 -->
        <Card title="自测原理">
          <div class="text-xs space-y-2 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-3 rounded-xl border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-blue-400">工作流程</p>
              <p>1. 生成临时自签名证书</p>
              <p>2. 启动本地 TLS/TLCP 服务器 (随机端口)</p>
              <p>3. 客户端连接服务器，完成握手</p>
              <p>4. 客户端发送消息，服务器回显</p>
              <p>5. 验证收发一致性</p>
            </div>
            <div class="p-3 rounded-xl border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-violet-400">PQC 混合模式</p>
              <p>启用后使用 X25519MLKEM768 作为首选密钥交换组，结合经典 X25519 和后量子 ML-KEM-768。</p>
            </div>
          </div>
        </Card>
      </div>

      <!-- 自测结果 -->
      <div class="space-y-3">
        <Card>
          <div class="flex items-center gap-2 mb-3">
            <span class="badge" :class="selfTestResult.success ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'">
              {{ selfTestResult.success ? '通过' : '未测试' }}
            </span>
            <p class="text-sm font-medium">自测结果</p>
          </div>

          <div v-if="selfTestResult.error" class="p-3 rounded-xl border border-red-500/20 bg-red-500/5 text-red-400 text-xs mb-3">
            {{ selfTestResult.error }}
          </div>

          <div v-if="selfTestResult.success" class="space-y-3">
            <div class="grid grid-cols-2 gap-2">
              <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <p class="text-[10px] text-muted mb-0.5">协议</p>
                <p class="text-sm font-semibold" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ selfTestResult.tlsVersion }}</p>
              </div>
              <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <p class="text-[10px] text-muted mb-0.5">握手耗时</p>
                <p class="text-sm font-semibold" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ selfTestResult.handshakeTimeMs }} ms</p>
              </div>
              <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <p class="text-[10px] text-muted mb-0.5">密码套件</p>
                <p class="text-xs font-semibold break-all" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ selfTestResult.cipherSuite }}</p>
              </div>
              <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <p class="text-[10px] text-muted mb-0.5">数据交换耗时</p>
                <p class="text-sm font-semibold" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ selfTestResult.exchangeTimeMs }} ms</p>
              </div>
            </div>

            <div v-if="selfTestResult.curveUsed" class="flex items-center gap-2 text-xs">
              <span class="text-muted">密钥交换:</span>
              <span class="font-mono" :class="selfTestResult.curveUsed.includes('PQC') ? 'text-violet-400' : ''">
                {{ selfTestResult.curveUsed }}
              </span>
            </div>

            <!-- 收发验证 -->
            <div class="p-3 rounded-xl border" :class="selfTestResult.sentMessage === selfTestResult.receivedMessage ? 'border-emerald-500/20 bg-emerald-500/5' : 'border-red-500/20 bg-red-500/5'">
              <div class="flex items-center gap-2 mb-2">
                <span class="text-xs font-bold" :class="selfTestResult.sentMessage === selfTestResult.receivedMessage ? 'text-emerald-400' : 'text-red-400'">
                  {{ selfTestResult.sentMessage === selfTestResult.receivedMessage ? '✓ 收发一致' : '✗ 收发不一致' }}
                </span>
              </div>
              <div class="space-y-1 text-[11px]">
                <p><span class="text-muted">发送:</span> <span class="font-mono">{{ selfTestResult.sentMessage }}</span></p>
                <p><span class="text-muted">接收:</span> <span class="font-mono">{{ selfTestResult.receivedMessage }}</span></p>
              </div>
            </div>
          </div>
        </Card>

        <!-- 证书信息 -->
        <Card v-if="selfTestResult.peerCertificates && selfTestResult.peerCertificates.length > 0">
          <div class="flex items-center gap-2 mb-3">
            <span class="badge bg-violet-500/20 text-violet-400">证书</span>
            <p class="text-sm font-medium">自签名测试证书</p>
          </div>
          <div v-for="(cert, idx) in selfTestResult.peerCertificates" :key="idx"
               class="p-3 rounded-xl border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
            <div class="space-y-1 text-[11px]">
              <p><span class="text-muted w-16 inline-block">Subject:</span> <span class="font-mono">{{ cert.subject }}</span></p>
              <p><span class="text-muted w-16 inline-block">有效期:</span> {{ cert.notBefore }} ~ {{ cert.notAfter }}</p>
              <p><span class="text-muted w-16 inline-block">算法:</span> {{ cert.keyAlgorithm }} / {{ cert.sigAlgorithm }}</p>
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
import { ref, reactive, onMounted } from 'vue'
import { storeToRefs } from 'pinia'
import { ShieldCheckIcon, LockIcon, FolderOpenIcon, ZapIcon, ChevronDownIcon } from '@lucide/vue'
import Card from '../components/Card.vue'
import Input from '../components/Input.vue'
import Button from '../components/Button.vue'
import PageLayout from '../components/PageLayout.vue'
import Dropdown from '../components/Dropdown.vue'
import ByteBadge from '../components/ByteBadge.vue'
import { TLSConnect, TLSSelfTest, ListTLSCipherSuites, ListTLCPCipherSuites, SelectFile, ReadFile } from '../../wailsjs/go/main/App'
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
  message: 'Hello from CryptoKit!',
  enablePQC: false,
})

const selfTesting = ref(false)
const selfTestResult = reactive({
  success: false,
  protocol: '',
  cipherSuite: '',
  cipherSuiteId: '',
  tlsVersion: '',
  handshakeTimeMs: 0,
  exchangeTimeMs: 0,
  peerCertificates: [],
  alpnProtocol: '',
  sessionReused: false,
  sentMessage: '',
  receivedMessage: '',
  curveUsed: '',
  error: '',
})

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

async function doSelfTest() {
  selfTesting.value = true
  selfTestResult.success = false
  selfTestResult.error = ''
  selfTestResult.peerCertificates = []

  try {
    const r = await TLSSelfTest({
      protocol: selfTest.protocol,
      message: selfTest.message || 'Hello from CryptoKit!',
      enablePQC: selfTest.enablePQC,
    })
    Object.assign(selfTestResult, r)
  } catch (e) {
    selfTestResult.error = String(e)
  } finally {
    selfTesting.value = false
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
