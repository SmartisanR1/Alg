<template>
  <PageLayout title="非对称算法" subtitle="RSA · SM2 · SM9 · ECDSA · ECDH · Ed25519 · X25519"
              icon-bg="bg-cyan-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <KeyIcon class="w-4 h-4 text-cyan-400" />
    </template>

    <template #actions>
      <Button variant="secondary" size="sm" @click="showPrinciple = true">
        <InfoIcon class="w-3.5 h-3.5" /> 算法原理
      </Button>
    </template>

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

    <!-- RSA -->
    <div v-if="activeTab === 'rsa'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="RSA 密钥生成">
          <div class="flex gap-2 mb-3">
            <Dropdown
              v-model="rsa.bits"
              :options="[
                { value: '1024', label: '1024 bit' },
                { value: '2048', label: '2048 bit' },
                { value: '3072', label: '3072 bit' },
                { value: '4096', label: '4096 bit' }
              ]"
              class="flex-1"
            />
            <Dropdown
              v-model="asymKeyFormat"
              :options="[
                { value: 'pem', label: 'PEM 格式' },
                { value: 'hex', label: 'HEX 格式' }
              ]"
              class="flex-1"
            />
            <Button variant="secondary" class="flex-1" @click="genRSAKey">
              <KeyIcon class="w-3.5 h-3.5" /> 生成密钥
            </Button>
          </div>
          
          <!-- Generated keys display -->
          <div v-if="rsaKeys.privateKey" class="space-y-2 animate-in fade-in">
            <div>
              <label class="input-label text-orange-300">私钥 ({{ asymKeyFormat.toUpperCase() }})</label>
              <div class="result-area !min-h-0 !p-2 text-orange-300 !text-[11px] break-all max-h-20 overflow-y-auto font-mono">
                {{ asymKeyFormat === 'pem' ? rsaKeys.privateKey : rsaKeys.privHex }}
              </div>
            </div>
            <div>
              <label class="input-label text-cyan-200">公钥 ({{ asymKeyFormat.toUpperCase() }})</label>
              <div class="result-area !min-h-0 !p-2 text-cyan-200 !text-[11px] break-all max-h-20 overflow-y-auto font-mono">
                {{ asymKeyFormat === 'pem' ? rsaKeys.publicKey : rsaKeys.pubHex }}
              </div>
            </div>
          </div>
        </Card>
        
        <Card title="算法参数">
          <div class="grid grid-cols-2 gap-3 mb-3">
            <div>
              <label class="input-label">填充模式</label>
              <Dropdown
                v-model="rsa.padding"
                :options="[
                  { value: 'PKCS1v15', label: 'PKCS#1 v1.5' },
                  { value: 'OAEP', label: 'OAEP (加密推荐)' },
                  { value: 'PSS', label: 'PSS (签名推荐)' }
                ]"
              />
            </div>
            <div>
              <label class="input-label">Hash 算法</label>
              <Dropdown
                v-model="rsa.hash"
                :options="[
                  { value: 'SHA256', label: 'SHA-256' },
                  { value: 'SHA384', label: 'SHA-384' },
                  { value: 'SHA512', label: 'SHA-512' },
                  { value: 'SHA1', label: 'SHA-1 (旧标准)' }
                ]"
              />
            </div>
          </div>
          <div>
            <label class="input-label">密钥内容 (PEM/Hex)</label>
            <textarea v-model="rsa.key" class="input text-[11px] font-mono" rows="2" placeholder="粘贴公钥(加密/验签)或私钥(解密/签名)..." />
          </div>
        </Card>
      </div>
      <div class="sym-main">
        <Card title="数据输入">
          <CryptoPanel v-model="rsa.data" label="待处理数据 (Hex)" type="textarea" :rows="4" clearable />
        </Card>
        
        <div class="grid grid-cols-2 gap-2">
          <Button variant="success" @click="rsaEncrypt"><LockIcon class="w-3.5 h-3.5"/>加密</Button>
          <Button variant="warning" @click="rsaDecrypt"><UnlockIcon class="w-3.5 h-3.5"/>解密</Button>
          <Button variant="success" @click="rsaSign"><PenIcon class="w-3.5 h-3.5"/>签名</Button>
          <Button variant="warning" @click="rsaVerify"><CheckCircleIcon class="w-3.5 h-3.5"/>验签</Button>
        </div>
        
        <ResultArea
          v-model="rsaResult.data"
          label="运算结果"
          :success="rsaResult.success"
          :error="rsaResult.error"
          copyable
        />
      </div>
    </div>

    <!-- SM2 -->
    <div v-if="activeTab === 'sm2'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <div class="flex gap-1 p-1 rounded-xl w-fit shrink-0 mb-1" :class="isDark ? 'bg-dark-card border border-dark-border' : 'bg-light-card border border-light-border'">
          <button v-for="s in sm2Subtabs" :key="s.id"
                  class="px-4 py-1.5 rounded-lg text-xs font-bold transition-all"
                  :class="sm2Sub === s.id ? (isDark ? 'bg-dark-accent text-white shadow-lg shadow-dark-accent/20' : 'bg-light-accent text-white shadow-md shadow-light-accent/20') : (isDark ? 'text-dark-muted hover:text-dark-text' : 'text-light-muted hover:text-light-text')"
                  @click="sm2Sub = s.id">
            {{ s.label }}
          </button>
        </div>

        <Card v-if="sm2Sub === 'keygen'" title="SM2 密钥对生成">
          <div class="flex gap-2 mb-4">
            <Dropdown
              v-model="asymKeyFormat"
              :options="[
                { value: 'pem', label: 'PEM 格式 (X.509/PKCS#8)' },
                { value: 'hex', label: '裸值 Hex (私钥32B / 公钥64B)' }
              ]"
              class="flex-1"
            />
            <Button variant="secondary" @click="genSM2Key">
              <KeyIcon class="w-3.5 h-3.5" /> 生成密钥对
            </Button>
          </div>
          <div v-if="sm2Keys.privateKey" class="space-y-3 animate-in fade-in">
            <div>
              <div class="flex justify-between mb-1.5">
                <label class="input-label !mb-0 text-orange-300">私钥 ({{ asymKeyFormat === 'hex' ? '裸值32字节' : 'PEM' }})</label>
                <button @click="copy(asymKeyFormat === 'pem' ? sm2Keys.privateKey : sm2Keys.rawPriv)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /> 复制</button>
              </div>
              <div class="result-area !min-h-[80px] text-orange-300 !text-[12px] break-all max-h-40 overflow-y-auto font-mono border-amber-400/20 bg-orange-400/15">
                {{ asymKeyFormat === 'pem' ? sm2Keys.privateKey : sm2Keys.rawPriv }}
              </div>
            </div>
            <div>
              <div class="flex justify-between mb-1.5">
                <label class="input-label !mb-0 text-cyan-200">公钥 ({{ asymKeyFormat === 'hex' ? '裸值64字节 X||Y' : 'PEM' }})</label>
                <button @click="copy(asymKeyFormat === 'pem' ? sm2Keys.publicKey : sm2Keys.rawPub)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /> 复制</button>
              </div>
              <div class="result-area !min-h-[60px] text-cyan-200 !text-[12px] break-all max-h-40 overflow-y-auto font-mono border-cyan-500/10 bg-cyan-500/5">
                {{ asymKeyFormat === 'pem' ? sm2Keys.publicKey : sm2Keys.rawPub }}
              </div>
            </div>
          </div>
          <div v-else class="flex-1 flex flex-col items-center justify-center text-dark-muted opacity-40 border-2 border-dashed border-dark-border rounded-xl mt-2">
            <KeyIcon class="w-10 h-10 mb-2" />
            <p class="text-xs">点击上方按钮生成符合国密标准的 SM2 密钥对</p>
          </div>
        </Card>

        <Card v-if="sm2Sub === 'enc'" title="SM2 加密/解密配置">
          <div class="grid grid-cols-1 gap-3">
            <CryptoPanel v-model="sm2Enc.publicKey" label="公钥 (PEM/Hex) — 用于加密" type="textarea" :rows="asymKeyFormat === 'hex' ? 2 : 3" clearable />
            <CryptoPanel v-model="sm2Enc.privateKey" label="私钥 (PEM/Hex) — 用于解密" type="textarea" :rows="asymKeyFormat === 'hex' ? 2 : 3" clearable />
          </div>
        </Card>

        <Card v-if="sm2Sub === 'sign'" title="SM2 签名/验签配置">
          <div class="grid grid-cols-1 gap-3">
            <CryptoPanel v-model="sm2Sign.privateKey" label="私钥 (PEM/Hex) — 用于签名" type="textarea" :rows="asymKeyFormat === 'hex' ? 2 : 3" clearable />
            <CryptoPanel v-model="sm2Sign.publicKey" label="公钥 (PEM/Hex) — 用于验签" type="textarea" :rows="asymKeyFormat === 'hex' ? 2 : 3" clearable />
            <div>
              <label class="input-label">用户标识 (IDA / 可选)</label>
              <Input v-model="sm2Sign.id" placeholder="默认: 1234567812345678" class="font-mono text-xs" />
            </div>
          </div>
        </Card>
      </div>

      <div class="sym-main">
        <!-- Data input for enc/sign modes -->
        <Card v-if="sm2Sub === 'enc'" title="数据输入">
          <CryptoPanel v-model="sm2Enc.data" label="待处理数据 (Hex)" type="textarea" :rows="4" clearable />
        </Card>
        <Card v-if="sm2Sub === 'sign'" title="数据输入">
          <CryptoPanel v-model="sm2Sign.data" label="待处理数据 (Hex)" type="textarea" :rows="4" clearable />
        </Card>

        <!-- Action buttons -->
        <div v-if="sm2Sub === 'enc'" class="grid grid-cols-2 gap-2">
          <Button variant="success" @click="sm2Encrypt"><LockIcon class="w-3.5 h-3.5" /> 加密</Button>
          <Button variant="warning" @click="sm2Decrypt"><UnlockIcon class="w-3.5 h-3.5" /> 解密</Button>
        </div>
        <div v-if="sm2Sub === 'sign'" class="grid grid-cols-2 gap-2">
          <Button variant="success" @click="doSM2Sign"><PenIcon class="w-3.5 h-3.5" /> 签名</Button>
          <Button variant="warning" @click="doSM2Verify"><CheckCircleIcon class="w-3.5 h-3.5" /> 验签</Button>
        </div>

        <!-- Result -->
        <ResultArea
          v-model="sm2Result.data"
          label="运算结果"
          :success="sm2Result.success"
          :error="sm2Result.error"
          copyable
        />
      </div>
    </div>

    <!-- SM9 -->
    <div v-if="activeTab === 'sm9'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <div class="card">
          <p class="card-title">SM9 标识密码 (IBC)</p>
          <div class="space-y-2">
            <div class="grid grid-cols-2 gap-2">
              <button @click="genSM9MasterKey" class="btn-secondary w-full justify-center">
                <KeyIcon class="w-3.5 h-3.5" /> 签名主密钥
              </button>
              <button @click="genSM9EncMasterKey" class="btn-secondary w-full justify-center">
                <LockIcon class="w-3.5 h-3.5" /> 加密主密钥
              </button>
            </div>
            <div v-if="sm9Master.publicKey" class="card !bg-transparent space-y-2 animate-in fade-in duration-300">
              <div>
                <label class="input-label text-orange-300">签名主私钥 (Hex)</label>
                <div class="result-area ck-key-hex !min-h-0 text-orange-300 text-[12px] break-all max-h-32 overflow-y-auto font-mono">{{ sm9Master.privateKey }}</div>
              </div>
              <div>
                <label class="input-label text-cyan-200">签名主公钥 (Hex)</label>
                <div class="result-area ck-key-hex !min-h-0 text-cyan-200 text-[12px] break-all max-h-32 overflow-y-auto font-mono">{{ sm9Master.publicKey }}</div>
              </div>
            </div>
            <div v-if="sm9EncMaster.publicKey" class="card !bg-transparent space-y-2 animate-in fade-in duration-300">
              <div>
                <label class="input-label text-orange-300">加密主私钥 (Hex)</label>
                <div class="result-area ck-key-hex !min-h-0 text-orange-300 text-[12px] break-all max-h-32 overflow-y-auto font-mono">{{ sm9EncMaster.privateKey }}</div>
              </div>
              <div>
                <label class="input-label text-cyan-200">加密主公钥 (Hex)</label>
                <div class="result-area ck-key-hex !min-h-0 text-cyan-200 text-[12px] break-all max-h-32 overflow-y-auto font-mono">{{ sm9EncMaster.publicKey }}</div>
              </div>
            </div>
          </div>
        </div>
        <Card>
          <div>
            <label class="input-label">用户标识 (UID / 标识即公钥)</label>
            <Input v-model="sm9.uid" placeholder="例如: alice@cryptokit.com" />
          </div>
          <CryptoPanel v-model="sm9.data" label="待处理数据 (Hex)" type="textarea" :rows="3" clearable />
          <div class="flex gap-2">
            <Button variant="success" class="flex-1" @click="doSM9Encrypt"><LockIcon class="w-3.5 h-3.5" />标识加密</Button>
            <Button variant="warning" class="flex-1" @click="doSM9Sign"><PenIcon class="w-3.5 h-3.5" />标识签名</Button>
          </div>
        </Card>
      </div>
      <div class="sym-main">
        <ResultArea
          v-model="sm9Result.data"
          label="运算结果"
          :success="sm9Result.success"
          :error="sm9Result.error"
          copyable
        />
      </div>
    </div>

    <!-- ECC -->
    <div v-if="activeTab === 'ecc'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="ECC 曲线密钥生成">
          <div class="flex gap-2 mb-4">
            <Dropdown
              v-model="ecc.curve"
              :options="[
                { value: 'P-256', label: 'NIST P-256' },
                { value: 'P-384', label: 'NIST P-384' },
                { value: 'P-521', label: 'NIST P-521' },
                { value: 'SM2', label: '国密 SM2' },
                { value: 'secp256k1', label: 'Bitcoin (secp256k1)' }
              ]"
              class="flex-1"
            />
            <Button variant="secondary" class="flex-1" @click="genECCKey">
              <KeyIcon class="w-3.5 h-3.5" /> 生成密钥
            </Button>
          </div>
          <div v-if="eccKeys.privateKey" class="space-y-3 animate-in fade-in duration-300">
            <div>
              <div class="flex justify-between mb-1">
                <label class="input-label !mb-0 text-orange-300">私钥 ({{ asymKeyFormat === 'hex' ? '裸值' : 'PEM' }})</label>
                <button @click="copy(asymKeyFormat === 'pem' ? eccKeys.privateKey : eccKeys.privHex)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="result-area !min-h-0 text-orange-300 !text-[12px] break-all max-h-40 overflow-y-auto font-mono">
                {{ asymKeyFormat === 'pem' ? eccKeys.privateKey : eccKeys.privHex }}
              </div>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="input-label !mb-0 text-cyan-200">公钥 ({{ asymKeyFormat === 'hex' ? '裸值 X||Y' : 'PEM' }})</label>
                <button @click="copy(asymKeyFormat === 'pem' ? eccKeys.publicKey : eccKeys.pubHex)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="result-area !min-h-0 text-cyan-200 !text-[12px] break-all max-h-32 overflow-y-auto font-mono">
                {{ asymKeyFormat === 'pem' ? eccKeys.publicKey : eccKeys.pubHex }}
              </div>
            </div>
          </div>
        </Card>
        <Card>
          <div>
            <label class="input-label">密钥内容 (PEM/Hex)</label>
            <textarea v-model="ecc.key" class="input text-[10px] font-mono" rows="3" placeholder="粘贴私钥(签名)或公钥(验签/ECDH)..." />
          </div>
          <div>
            <label class="input-label">对方公钥 (仅 ECDH 使用)</label>
            <textarea v-model="ecc.peerKey" class="input text-[10px] font-mono" rows="2" placeholder="密钥交换时填入对方公钥..." />
          </div>
          <CryptoPanel v-model="ecc.data" label="待处理数据 (Hex)" type="input" clearable />
        </Card>
      </div>
      <div class="sym-main">
        <div class="grid grid-cols-3 gap-2">
          <Button variant="success" @click="eccSign"><PenIcon class="w-3.5 h-3.5"/>签名</Button>
          <Button variant="warning" @click="eccVerify"><CheckCircleIcon class="w-3.5 h-3.5"/>验签</Button>
          <Button variant="primary" @click="ecdhCompute"><LinkIcon class="w-3.5 h-3.5"/>ECDH</Button>
        </div>
        <ResultArea
          v-model="eccResult.data"
          label="运算结果"
          :success="eccResult.success"
          :error="eccResult.error"
          copyable
        />
      </div>
    </div>

    <!-- Ed25519 / X25519 -->
    <div v-if="activeTab === 'curve25519'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="Curve25519 系列操作">
          <div class="flex gap-2 mb-3">
            <Button variant="secondary" class="flex-1" @click="genX25519">
              <KeyIcon class="w-3 h-3" /> X25519 密钥对
            </Button>
            <Button variant="secondary" class="flex-1" @click="genEd25519">
              <KeyIcon class="w-3 h-3" /> Ed25519 密钥对
            </Button>
          </div>
          <div v-if="c25519.privateKey" class="space-y-2 animate-in fade-in duration-300">
            <div>
              <label class="input-label text-orange-300">私钥 (Hex)</label>
              <div class="result-area !min-h-0 text-orange-300 text-[12px] font-mono break-all">{{ c25519.privateKey }}</div>
            </div>
            <div>
              <label class="input-label text-cyan-200">公钥 (Hex)</label>
              <div class="result-area !min-h-0 text-cyan-200 text-[12px] font-mono break-all">{{ c25519.publicKey }}</div>
            </div>
          </div>
        </Card>
        <Card>
          <div>
            <label class="input-label">私钥 (Hex)</label>
            <Input v-model="c25519.usePriv" class="font-mono text-[10px]" />
          </div>
          <div>
            <label class="input-label">对方公钥 / 待验证签名 (Hex)</label>
            <Input v-model="c25519.peerPub" class="font-mono text-[10px]" />
          </div>
          <CryptoPanel v-model="c25519.data" label="待处理数据 (Hex)" type="input" clearable />
        </Card>
      </div>
      <div class="sym-main">
        <div class="grid grid-cols-2 gap-2">
          <Button variant="primary" @click="x25519Exchange"><LinkIcon class="w-3.5 h-3.5"/>X25519 交换</Button>
          <Button variant="success" @click="ed25519Sign"><PenIcon class="w-3.5 h-3.5"/>Ed25519 签名</Button>
          <Button variant="warning" class="col-span-2" @click="ed25519Verify"><CheckCircleIcon class="w-3.5 h-3.5"/>Ed25519 验签</Button>
        </div>
        <ResultArea
          v-model="c25519Result.data"
          label="运算结果"
          :success="c25519Result.success"
          :error="c25519Result.error"
          copyable
        />
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted } from 'vue'
import { storeToRefs } from 'pinia'
import { useRoute } from 'vue-router'
import { KeyIcon, LockIcon, UnlockIcon, PenIcon, CheckCircleIcon, CopyIcon, LinkIcon, InfoIcon, XIcon, ShieldCheckIcon, ZapIcon } from 'lucide-vue-next'
import PageLayout from '../components/PageLayout.vue'
import Card from '../components/Card.vue'
import Input from '../components/Input.vue'
import InputWithBytes from '../components/InputWithBytes.vue'
import Button from '../components/Button.vue'
import ResultArea from '../components/ResultArea.vue'
import AlgorithmDrawer from '../components/AlgorithmDrawer.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import Dropdown from '../components/Dropdown.vue'
import {
  RSAGenerateKey, RSAEncrypt, RSADecrypt, RSASign, RSAVerify,
  ECCGenerateKey, ECCSign, ECCVerify, ECDHCompute,
  X25519KeyGen, X25519Exchange, Ed25519KeyGen, Ed25519Sign, Ed25519Verify,
  Ed448KeyGen, Ed448Sign, Ed448Verify,
  SM2GenerateKey, SM2GenerateRawKey, SM2Encrypt, SM2Decrypt, SM2Sign, SM2Verify,
  SM9GenerateMasterKey, SM9GenerateEncMasterKey, SM9Sign, SM9Encrypt
} from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const route = useRoute()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'rsa', label: 'RSA' },
  { id: 'sm2', label: 'SM2' },
  { id: 'sm9', label: 'SM9 (IBC)' },
  { id: 'ecc', label: 'ECC (ECDSA/ECDH)' },
  { id: 'curve25519', label: 'Ed25519 / X25519' },
]
const activeTab = ref('rsa')

onMounted(() => {
  if (route.query.tab) {
    const tab = tabs.find(t => t.id === route.query.tab)
    if (tab) activeTab.value = tab.id
  }
})

watch(() => route.query.tab, (newTab) => {
  if (newTab && tabs.find(t => t.id === newTab)) {
    activeTab.value = newTab
  }
})

// Principles modal / info
const showPrinciple = ref(false)
const principles = {
  rsa: {
    title: 'RSA 算法原理',
    content: 'RSA 是最早的非对称加密算法之一，安全性基于大整数分解难题。加密和签名时可选择不同的填充模式：\n1. PKCS#1 v1.5: 传统模式，简单但对某些攻击较脆弱。\n2. OAEP (Optimal Asymmetric Encryption Padding): 推荐用于加密，引入随机性提高安全性。\n3. PSS (Probabilistic Signature Scheme): 推荐用于签名，安全性证明更强。'
  },
  sm2: {
    title: 'SM2 算法原理',
    content: 'SM2 是国家密码管理局发布的椭圆曲线公钥密码算法。安全性基于椭圆曲线离散对数难题。\n- 曲线参数：sm2p256v1 (256位)\n- 功能：包括数字签名、公钥加密、密钥交换。\n- 特点：在相同安全强度下，密钥长度远小于 RSA，计算速度更快。'
  },
  sm9: {
    title: 'SM9 算法原理',
    content: 'SM9 是标识密码算法(IBC)。无需颁发数字证书，直接以用户标识(如邮件、手机号)作为公钥。\n- 技术基础：基于双线性对(Pairing)技术。\n- 优势：简化了密钥管理和分发流程，适用于物联网、大规模用户环境。'
  },
  ecc: {
    title: 'ECC 椭圆曲线原理',
    content: 'ECC (Elliptic Curve Cryptography) 安全性基于椭圆曲线离散对数难题。相比 RSA，ECC 在相同安全级别下密钥更短，计算更快。广泛用于 ECDSA 签名和 ECDH 密钥交换。支持 NIST 曲线、国密 SM2 和 Bitcoin 的 secp256k1。'
  },
  curve25519: {
    title: 'Curve25519 原理',
    content: '由 Daniel J. Bernstein 设计，旨在提供极高性能且不牺牲安全性. X25519 用于 Diffie-Hellman 密钥交换，Ed25519 用于数字签名。它们的设计避免了传统 ECC 曲线中的许多潜在陷阱（如侧信道攻击）。'
  }
}

const currentPrinciple = computed(() => principles[activeTab.value])

const parsedPrinciples = computed(() => {
  if (!currentPrinciple.value) return []
  const lines = currentPrinciple.value.content.split('\n')
  const sections = []
  let currentSection = null

  lines.forEach(line => {
    if ((line.includes(':') || line.includes('：')) && !line.startsWith('•')) {
      const splitChar = line.includes(':') ? ':' : '：'
      const [title, ...rest] = line.split(splitChar)
      currentSection = { title: title.trim(), content: [rest.join(splitChar).trim()] }
      sections.push(currentSection)
    } else if (currentSection) {
      if (line.trim()) currentSection.content.push(line.trim())
    }
  })

  if (sections.length === 0) {
    return [{ title: '详细说明', content: lines.filter(l => l.trim()) }]
  }
  return sections
})

const asymKeyFormat = ref('hex')

// RSA
const rsa = reactive({ bits: '2048', padding: 'OAEP', hash: 'SHA256', key: '', data: '' })
const rsaKeys = reactive({ privateKey: '', publicKey: '', privHex: '', pubHex: '' })
const rsaResult = reactive({ data: '', error: '', success: null })
const rsaSignature = ref('')

async function genRSAKey() {
  const r = await RSAGenerateKey(parseInt(rsa.bits))
  if (r.success) { 
    rsaKeys.privateKey = r.privateKey; rsaKeys.publicKey = r.publicKey 
    rsaKeys.privHex = r.privHex; rsaKeys.pubHex = r.pubHex
    rsa.key = asymKeyFormat.value === 'pem' ? r.publicKey : r.pubHex
  }
}
async function rsaEncrypt() {
  rsa.key = asymKeyFormat.value === 'pem' ? rsaKeys.publicKey : rsaKeys.pubHex
  const r = await RSAEncrypt({ key: rsa.key, data: rsa.data, padding: rsa.padding, hash: rsa.hash })
  rsaResult.data = r.data; rsaResult.error = r.error; rsaResult.success = r.success
}
async function rsaDecrypt() {
  rsa.key = asymKeyFormat.value === 'pem' ? rsaKeys.privateKey : rsaKeys.privHex
  if (rsaResult.data && rsaResult.success) rsa.data = rsaResult.data
  const r = await RSADecrypt({ key: rsa.key, data: rsa.data, padding: rsa.padding, hash: rsa.hash })
  rsaResult.data = r.data; rsaResult.error = r.error; rsaResult.success = r.success
}
async function rsaSign() {
  rsa.key = asymKeyFormat.value === 'pem' ? rsaKeys.privateKey : rsaKeys.privHex
  const r = await RSASign({ privateKey: rsa.key, data: rsa.data, hash: rsa.hash, padding: rsa.padding === 'PSS' ? 'PSS' : 'PKCS1v15' })
  rsaResult.data = r.data; rsaResult.error = r.error; rsaResult.success = r.success
  if (r.success) rsaSignature.value = r.data
}
async function rsaVerify() {
  rsa.key = asymKeyFormat.value === 'pem' ? rsaKeys.publicKey : rsaKeys.pubHex
  const sig = rsaSignature.value || rsaResult.data
  const r = await RSAVerify({ publicKey: rsa.key, data: rsa.data, signature: sig, hash: rsa.hash, padding: rsa.padding === 'PSS' ? 'PSS' : 'PKCS1v15' })
  rsaResult.data = r.data; rsaResult.error = r.error; rsaResult.success = r.success
}

// SM2
const sm2Subtabs = [
  { id: 'keygen', label: '密钥生成' },
  { id: 'enc', label: '加密/解密' },
  { id: 'sign', label: '签名/验签' },
]
const sm2Sub = ref('keygen')
const sm2Keys = reactive({ privateKey: '', publicKey: '', privHex: '', pubHex: '', rawPriv: '', rawPub: '' })
const sm2Enc = reactive({ publicKey: '', privateKey: '', data: '' })
const sm2EncResult = reactive({ data: '', error: '', success: null })
const sm2Sign = reactive({ privateKey: '', publicKey: '', id: '', data: '' })
const sm2SignResult = reactive({ data: '', error: '', success: null })
const sm2Signature = ref('')

// ── 统一结果展示 ────────────────────────────────────────────────
const sm2Result = computed(() => {
  if (sm2Sub.value === 'enc') return sm2EncResult
  if (sm2Sub.value === 'sign') return sm2SignResult
  return { data: '', error: '', success: null }
})

async function genSM2Key() {
  const r = await SM2GenerateRawKey()
  if (r.success) { 
    sm2Keys.privateKey = r.privateKey; sm2Keys.publicKey = r.publicKey 
    sm2Keys.privHex = r.privHex; sm2Keys.pubHex = r.pubHex
    sm2Keys.rawPriv = r.rawPriv; sm2Keys.rawPub = r.rawPub
    if (asymKeyFormat.value === 'hex') {
      sm2Enc.publicKey = r.rawPub; sm2Enc.privateKey = r.rawPriv
      sm2Sign.publicKey = r.rawPub; sm2Sign.privateKey = r.rawPriv
    } else {
      sm2Enc.publicKey = r.publicKey; sm2Enc.privateKey = r.privateKey
      sm2Sign.publicKey = r.publicKey; sm2Sign.privateKey = r.privateKey
    }
  }
}
async function sm2Encrypt() {
  sm2Enc.publicKey = asymKeyFormat.value === 'hex' ? sm2Keys.rawPub : sm2Keys.publicKey
  const r = await SM2Encrypt({ key: sm2Enc.publicKey, data: sm2Enc.data, mode: 'C1C3C2' })
  sm2EncResult.data = r.data; sm2EncResult.error = r.error; sm2EncResult.success = r.success
}
async function sm2Decrypt() {
  sm2Enc.privateKey = asymKeyFormat.value === 'hex' ? sm2Keys.rawPriv : sm2Keys.privateKey
  if (sm2EncResult.data) sm2Enc.data = sm2EncResult.data
  const r = await SM2Decrypt({ key: sm2Enc.privateKey, data: sm2Enc.data, mode: 'C1C3C2' })
  sm2EncResult.data = r.data; sm2EncResult.error = r.error; sm2EncResult.success = r.success
}
async function doSM2Sign() {
  sm2Sign.privateKey = asymKeyFormat.value === 'hex' ? sm2Keys.rawPriv : sm2Keys.privateKey
  const r = await SM2Sign({ privateKey: sm2Sign.privateKey, data: sm2Sign.data, id: sm2Sign.id })
  sm2SignResult.data = r.data; sm2SignResult.error = r.error; sm2SignResult.success = r.success
  if (r.success) sm2Signature.value = r.data
}
async function doSM2Verify() {
  sm2Sign.publicKey = asymKeyFormat.value === 'hex' ? sm2Keys.rawPub : sm2Keys.publicKey
  const sig = sm2Signature.value || sm2SignResult.data
  const r = await SM2Verify({ publicKey: sm2Sign.publicKey, data: sm2Sign.data, signature: sig, id: sm2Sign.id })
  sm2SignResult.data = r.data; sm2SignResult.error = r.error; sm2SignResult.success = r.success
}

// SM9
const sm9Master = reactive({ privateKey: '', publicKey: '' })
const sm9EncMaster = reactive({ privateKey: '', publicKey: '' })
const sm9 = reactive({ uid: '', data: '' })
const sm9Result = reactive({ data: '', error: '', success: null })

async function genSM9MasterKey() {
  const r = await SM9GenerateMasterKey()
  if (r.success) { sm9Master.privateKey = r.masterPrivateKey; sm9Master.publicKey = r.masterPublicKey }
}
async function genSM9EncMasterKey() {
  const r = await SM9GenerateEncMasterKey()
  if (r.success) { sm9EncMaster.privateKey = r.masterPrivateKey; sm9EncMaster.publicKey = r.masterPublicKey }
}
async function doSM9Encrypt() {
  const r = await SM9Encrypt({ masterPublicKey: sm9EncMaster.publicKey, uid: sm9.uid, data: sm9.data })
  sm9Result.data = r.data; sm9Result.error = r.error; sm9Result.success = r.success
}
async function doSM9Sign() {
  const r = await SM9Sign({ masterPrivateKey: sm9Master.privateKey, uid: sm9.uid, data: sm9.data })
  sm9Result.data = r.data; sm9Result.error = r.error; sm9Result.success = r.success
}

// ECC
const ecc = reactive({ curve: 'P-256', hash: 'SHA256', key: '', peerKey: '', data: '' })
const eccKeys = reactive({ privateKey: '', publicKey: '', privHex: '', pubHex: '' })
const eccResult = reactive({ data: '', error: '', success: null })

async function genECCKey() {
  const r = await ECCGenerateKey(ecc.curve)
  if (r.success) { 
    eccKeys.privateKey = r.privateKey; eccKeys.publicKey = r.publicKey 
    eccKeys.privHex = r.privHex; eccKeys.pubHex = r.pubHex
    ecc.key = asymKeyFormat.value === 'pem' ? r.publicKey : r.pubHex
  }
}
async function eccSign() {
  const r = await ECCSign({ privateKey: ecc.key, data: ecc.data, hash: ecc.hash, curve: ecc.curve })
  eccResult.data = r.data; eccResult.error = r.error; eccResult.success = r.success
}
async function eccVerify() {
  const r = await ECCVerify({ publicKey: ecc.key, data: ecc.data, signature: eccResult.data, hash: ecc.hash, curve: ecc.curve })
  eccResult.data = r.data; eccResult.error = r.error; eccResult.success = r.success
}
async function ecdhCompute() {
  const r = await ECDHCompute({ privateKey: ecc.key, peerPublicKey: ecc.peerKey, curve: ecc.curve })
  eccResult.data = r.data; eccResult.error = r.error; eccResult.success = r.success
}

// Curve25519
const c25519 = reactive({ privateKey: '', publicKey: '', usePriv: '', peerPub: '', data: '' })
const c25519Result = reactive({ data: '', error: '', success: null })

async function genX25519() {
  const r = await X25519KeyGen()
  if (r.success) { c25519.privateKey = r.privateKey; c25519.publicKey = r.publicKey; c25519.usePriv = r.privateKey }
}
async function genEd25519() {
  const r = await Ed25519KeyGen()
  if (r.success) { c25519.privateKey = r.privateKey; c25519.publicKey = r.publicKey; c25519.usePriv = r.privateKey }
}
async function x25519Exchange() {
  const r = await X25519Exchange({ privateKey: c25519.usePriv, peerPublicKey: c25519.peerPub })
  c25519Result.data = r.data; c25519Result.error = r.error; c25519Result.success = r.success
}
async function ed25519Sign() {
  const r = await Ed25519Sign({ privateKey: c25519.usePriv, data: c25519.data })
  c25519Result.data = r.data; c25519Result.error = r.error; c25519Result.success = r.success
}
async function ed25519Verify() {
  const r = await Ed25519Verify({ publicKey: c25519.publicKey, data: c25519.data, signature: c25519Result.data })
  c25519Result.data = r.data; c25519Result.error = r.error; c25519Result.success = r.success
}

async function copy(t) {
  if (!t) return
  await navigator.clipboard.writeText(t)
  store.showToast('已复制')
}
</script>

<style scoped>
.sym-workbench {
  display: grid;
  grid-template-columns: minmax(400px, 1.2fr) 1fr;
  gap: 12px;
  align-items: start;
}

.sym-side,
.sym-main {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

@media (max-width: 1080px) {
  .sym-workbench {
    grid-template-columns: 1fr;
  }
}
</style>
