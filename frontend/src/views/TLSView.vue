<template>
  <PageLayout title="TLS / TLCP 连接测试" subtitle="TLS 1.0-1.3 · 国密 TLCP 1.1 · 证书详情查看"
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
          <div class="flex items-center gap-2 mb-3">
            <input type="checkbox" v-model="form.insecureSkipVerify" id="skip-verify" class="rounded" />
            <label for="skip-verify" class="text-xs">跳过证书验证 (InsecureSkipVerify)</label>
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
                <textarea v-model="form.caCertPEM" rows="2" class="ck-textarea flex-1" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                <Button variant="tool" size="sm" @click="loadFile('caCertPEM')"><FolderOpenIcon class="w-3 h-3" /></Button>
              </div>
            </div>
            <div>
              <label class="input-label">签名证书 (PEM)</label>
              <div class="flex gap-1">
                <textarea v-model="form.clientCertPEM" rows="2" class="ck-textarea flex-1" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                <Button variant="tool" size="sm" @click="loadFile('clientCertPEM')"><FolderOpenIcon class="w-3 h-3" /></Button>
              </div>
            </div>
            <div>
              <label class="input-label">签名私钥 (PEM)</label>
              <div class="flex gap-1">
                <textarea v-model="form.clientKeyPEM" rows="2" class="ck-textarea flex-1" placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
                <Button variant="tool" size="sm" @click="loadFile('clientKeyPEM')"><FolderOpenIcon class="w-3 h-3" /></Button>
              </div>
            </div>
            <template v-if="form.protocol === 'tlcp'">
              <div>
                <label class="input-label text-violet-400">加密证书 (PEM) — TLCP</label>
                <div class="flex gap-1">
                  <textarea v-model="form.clientEncCertPEM" rows="2" class="ck-textarea flex-1" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                  <Button variant="tool" size="sm" @click="loadFile('clientEncCertPEM')"><FolderOpenIcon class="w-3 h-3" /></Button>
                </div>
              </div>
              <div>
                <label class="input-label text-violet-400">加密私钥 (PEM) — TLCP</label>
                <div class="flex gap-1">
                  <textarea v-model="form.clientEncKeyPEM" rows="2" class="ck-textarea flex-1" placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
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
            <span class="badge" :class="result.success ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'">
              {{ result.success ? '已连接' : '未连接' }}
            </span>
            <p class="text-sm font-medium">连接结果</p>
          </div>

          <div v-if="result.error" class="p-3 rounded-xl border border-red-500/20 bg-red-500/5 text-red-400 text-xs mb-3">
            {{ result.error }}
          </div>

          <div v-if="result.success" class="space-y-3">
            <!-- 连接信息 -->
            <div class="grid grid-cols-2 gap-2">
              <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <p class="text-[10px] text-muted mb-0.5">协议版本</p>
                <p class="text-sm font-semibold" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ result.tlsVersion }}</p>
              </div>
              <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <p class="text-[10px] text-muted mb-0.5">握手耗时</p>
                <p class="text-sm font-semibold" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ result.handshakeTimeMs }} ms</p>
              </div>
              <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <p class="text-[10px] text-muted mb-0.5">密码套件</p>
                <p class="text-xs font-semibold break-all" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ result.cipherSuite }}</p>
              </div>
              <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <p class="text-[10px] text-muted mb-0.5">套件 ID</p>
                <p class="text-sm font-mono font-semibold" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ result.cipherSuiteId }}</p>
              </div>
            </div>

            <div v-if="result.serverName" class="flex items-center gap-2 text-xs">
              <span class="text-muted">SNI:</span>
              <span class="font-mono" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ result.serverName }}</span>
            </div>
            <div v-if="result.alpnProtocol" class="flex items-center gap-2 text-xs">
              <span class="text-muted">ALPN:</span>
              <span class="font-mono" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ result.alpnProtocol }}</span>
            </div>
            <div class="flex items-center gap-2 text-xs">
              <span class="text-muted">会话复用:</span>
              <span :class="result.sessionReused ? 'text-emerald-400' : 'text-muted'">{{ result.sessionReused ? '是' : '否' }}</span>
            </div>
          </div>
        </Card>

        <!-- 证书信息 -->
        <Card v-if="result.peerCertificates && result.peerCertificates.length > 0">
          <div class="flex items-center gap-2 mb-3">
            <span class="badge bg-violet-500/20 text-violet-400">证书</span>
            <p class="text-sm font-medium">服务器证书链 ({{ result.peerCertificates.length }})</p>
          </div>
          <div class="space-y-3">
            <div v-for="(cert, idx) in result.peerCertificates" :key="idx"
                 class="p-3 rounded-xl border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
              <div class="flex items-center gap-2 mb-2">
                <span class="text-xs font-bold px-2 py-0.5 rounded" :class="cert.isCA ? 'bg-amber-500/20 text-amber-400' : 'bg-emerald-500/20 text-emerald-400'">
                  {{ cert.isCA ? 'CA' : (idx === 0 ? 'Leaf' : 'Intermediate') }}
                </span>
                <span class="text-xs text-muted">#{{ idx + 1 }}</span>
              </div>
              <div class="space-y-1 text-[11px]">
                <p><span class="text-muted w-16 inline-block">Subject:</span> <span class="font-mono break-all">{{ cert.subject }}</span></p>
                <p><span class="text-muted w-16 inline-block">Issuer:</span> <span class="font-mono break-all">{{ cert.issuer }}</span></p>
                <p><span class="text-muted w-16 inline-block">有效期:</span> {{ cert.notBefore }} ~ {{ cert.notAfter }}</p>
                <p><span class="text-muted w-16 inline-block">算法:</span> {{ cert.keyAlgorithm }} / {{ cert.sigAlgorithm }}</p>
                <p><span class="text-muted w-16 inline-block">序列号:</span> <span class="font-mono">{{ cert.serialNumber }}</span></p>
                <p v-if="cert.dnsNames && cert.dnsNames.length"><span class="text-muted w-16 inline-block">DNS:</span> {{ cert.dnsNames.join(', ') }}</p>
                <p v-if="cert.ipAddresses && cert.ipAddresses.length"><span class="text-muted w-16 inline-block">IP:</span> {{ cert.ipAddresses.join(', ') }}</p>
                <div class="mt-1">
                  <p class="text-muted mb-0.5">指纹 (SHA-256):</p>
                  <p class="font-mono text-[10px] break-all bg-black/5 dark:bg-white/5 p-1.5 rounded">{{ cert.fingerprint }}</p>
                </div>
              </div>
            </div>
          </div>
        </Card>
      </div>
    </div>

    <!-- 套件列表 -->
    <div v-if="activeTab === 'suites'" class="grid grid-cols-2 gap-4 animate-fade-in">
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
  </PageLayout>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { storeToRefs } from 'pinia'
import { ShieldCheckIcon, LockIcon, FolderOpenIcon } from '@lucide/vue'
import Card from '../components/Card.vue'
import Input from '../components/Input.vue'
import Button from '../components/Button.vue'
import PageLayout from '../components/PageLayout.vue'
import Dropdown from '../components/Dropdown.vue'
import { TLSConnect, ListTLSCipherSuites, ListTLCPCipherSuites, SelectFile, ReadFile } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'connect', label: '连接测试' },
  { id: 'suites', label: '密码套件' },
]
const activeTab = ref('connect')

const form = reactive({
  host: '',
  port: 443,
  protocol: 'tls1.2',
  serverName: '',
  insecureSkipVerify: true,
  caCertPEM: '',
  clientCertPEM: '',
  clientKeyPEM: '',
  clientEncCertPEM: '',
  clientEncKeyPEM: '',
})

const connecting = ref(false)
const result = reactive({
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
  error: '',
})

const tlsCipherSuites = ref([])
const tlcpCipherSuites = ref([])

async function doConnect() {
  if (!form.host) return
  connecting.value = true
  result.success = false
  result.error = ''
  result.peerCertificates = []

  try {
    const r = await TLSConnect({
      host: form.host,
      port: form.port || 443,
      protocol: form.protocol,
      serverName: form.serverName,
      insecureSkipVerify: form.insecureSkipVerify,
      caCertPEM: form.caCertPEM,
      clientCertPEM: form.clientCertPEM,
      clientKeyPEM: form.clientKeyPEM,
      clientEncCertPEM: form.clientEncCertPEM,
      clientEncKeyPEM: form.clientEncKeyPEM,
      timeoutMs: 10000,
    })
    Object.assign(result, r)
  } catch (e) {
    result.error = String(e)
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
