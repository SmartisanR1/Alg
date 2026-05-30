<template>
  <PageLayout title="金融数据密码" subtitle="磁条 / IC卡 MAC · PIN · CVV/PVV · 分散/密钥 · EMV"
              icon-bg="bg-indigo-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <FingerprintIcon class="w-4 h-4 text-orange-300" />
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
      :icon="InfoIcon"
      @close="showPrinciple = false"
    >
      <div v-for="(section, idx) in parsedPrinciples" :key="idx">
        <h4>{{ section.title }}</h4>
        <p v-for="(line, lIdx) in section.content" :key="lIdx" class="principle-line">
          {{ line }}
        </p>
      </div>
    </AlgorithmDrawer>

    <!-- MAC -->
    <div v-if="activeTab === 'mac'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="3DES Retail MAC" class="space-y-2">
          <CryptoPanel v-model="retail.key" label="密钥 (Hex)" type="input" placeholder="K1K2 或 K1K2K3..." />
          <CryptoPanel v-model="retail.data" label="数据 (Hex)" type="textarea" :rows="3" clearable />
          <div class="flex gap-2">
            <Dropdown
              v-model="retail.padding"
              :options="[
                { value: 'ISO9797-1-P2', label: 'P2 (0x80...)' },
                { value: 'ISO9797-1-P1', label: 'P1 (0x00...)' }
              ]"
              class="flex-1"
            />
            <Button variant="primary" class="justify-center shrink-0" @click="doRetailMAC">计算 MAC</Button>
          </div>
        </Card>

        <Card title="SM4-CBC-MAC" class="space-y-2">
          <CryptoPanel v-model="sm4mac.key" label="密钥 (Hex)" type="input" placeholder="32位Hex..." />
          <CryptoPanel v-model="sm4mac.data" label="数据 (Hex)" type="textarea" :rows="3" clearable />
          <div class="flex gap-2">
            <Dropdown
              v-model="sm4mac.padding"
              :options="[
                { value: 'ISO9797-1-P2', label: 'P2 (0x80...)' },
                { value: 'ISO9797-1-P1', label: 'P1' }
              ]"
              class="flex-1"
            />
            <Button variant="secondary" class="justify-center shrink-0" @click="doSM4MAC">SM4-CBC-MAC</Button>
          </div>
        </Card>

        <Card title="SM4-CMAC" class="space-y-2">
          <CryptoPanel v-model="sm4cmac.key" label="密钥 (Hex)" type="input" placeholder="32位Hex..." />
          <CryptoPanel v-model="sm4cmac.data" label="数据 (Hex)" type="textarea" :rows="3" clearable />
          <div class="flex gap-2">
            <Dropdown
              v-model="sm4cmac.padding"
              :options="[
                { value: 'ISO9797-1-P2', label: 'P2 (0x80...)' },
                { value: 'ISO9797-1-P1', label: 'P1' }
              ]"
              class="flex-1"
            />
            <Button variant="primary" class="justify-center shrink-0" @click="doSM4CMAC">SM4-CMAC</Button>
          </div>
        </Card>
      </div>

      <div class="sym-side">
        <Card title="Retail MAC 结果">
          <ResultArea
            :modelValue="retailResult.data"
            :error="retailResult.error"
            :success="retailResult.success"
            label="Retail MAC"
            copyable
          />
        </Card>
        <Card title="SM4-CBC-MAC 结果">
          <ResultArea
            :modelValue="sm4macResult.data"
            :error="sm4macResult.error"
            :success="sm4macResult.success"
            label="SM4-CBC-MAC"
            copyable
          />
        </Card>
        <Card title="SM4-CMAC 结果">
          <ResultArea
            :modelValue="sm4cmacResult.data"
            :error="sm4cmacResult.error"
            :success="sm4cmacResult.success"
            label="SM4-CMAC"
            copyable
          />
        </Card>
        <Card title="算法原理">
          <div class="space-y-2 text-sm leading-5" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="card">
              <p class="card-title text-violet-400 text-[13px]">Retail MAC</p>
              <p class="text-[13px]">先做 CBC-MAC，再经过 K2 解密和 K3 加密，常见于传统银行卡报文认证。</p>
            </div>
            <div class="card">
              <p class="card-title text-emerald-400 text-[13px]">SM4-CBC-MAC</p>
              <p class="text-[13px]">以全零 IV 做 CBC 链运算，最后一个密文分组即为认证结果，适合国密场景。</p>
            </div>
            <div class="card">
              <p class="card-title text-orange-300 text-[13px]">SM4-CMAC</p>
              <p class="text-[13px]">基于子密钥派生做分组认证，结构更规范，适合需要稳定消息认证的金融报文。</p>
            </div>
          </div>
        </Card>
      </div>
    </div>

    <!-- PIN -->
    <div v-if="activeTab === 'pin'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="PIN Block 生成" class="space-y-2">
          <Dropdown
            v-model="pin.format"
            :options="[
              { value: 'ISO-0', label: 'ISO-0 (PIN ^ PAN)' },
              { value: 'ISO-3', label: 'ISO-3 (随机填充)' }
            ]"
          />
          <div class="grid grid-cols-2 gap-2">
            <Input v-model="pin.pin" class="font-mono" placeholder="PIN (4-12位)" />
            <Input v-model="pin.pan" class="font-mono" placeholder="PAN" />
          </div>
          <Button variant="primary" block @click="genPINBlock">生成 PIN Block</Button>
        </Card>

        <Card title="PIN Block 加/解密" class="space-y-2">
          <Dropdown
            v-model="pinCryptoMode"
            :options="[
              { value: '3DES', label: '3DES' },
              { value: 'SM4', label: 'SM4' },
              { value: 'SM2', label: 'SM2' }
            ]"
          />
          <div class="relative">
            <CryptoPanel v-if="pinCryptoMode !== 'SM2'" v-model="pin.key" label="密钥 (Hex)" type="input" :placeholder="pinCryptoMode === 'SM4' ? '32位...' : '32/48位...'" />
            <CryptoPanel v-if="pinCryptoMode === 'SM2'" v-model="sm2pin.key" label="SM2密钥 (Hex)" type="input" placeholder="公钥/私钥Hex..." />
            <Button variant="tool" size="sm" v-if="pinCryptoMode !== 'SM2'" @click="genPINKey" class="absolute right-8 top-1/2 -translate-y-1/2 ck-mini-trigger">⚡</Button>
            <Button variant="tool" size="sm" v-if="pinCryptoMode === 'SM2'" @click="genSM2Key" class="absolute right-8 top-1/2 -translate-y-1/2 ck-mini-trigger">⚡</Button>
          </div>
          <CryptoPanel v-model="pin.block" label="PIN Block (Hex)" type="input" placeholder="8字节..." />
          <div class="grid grid-cols-2 gap-2">
            <Button variant="primary" v-if="pinCryptoMode === '3DES'" @click="encryptPINBlock" class="justify-center">加密</Button>
            <Button variant="primary" v-if="pinCryptoMode === 'SM4'" @click="sm4EncryptPIN" class="justify-center">SM4加密</Button>
            <Button variant="primary" v-if="pinCryptoMode === 'SM2'" @click="sm2EncryptPIN" class="justify-center">SM2加密</Button>
            <Button variant="secondary" v-if="pinCryptoMode === '3DES'" @click="decryptPINBlock" class="justify-center">解密</Button>
            <Button variant="secondary" v-if="pinCryptoMode === 'SM4'" @click="sm4DecryptPIN" class="justify-center">SM4解密</Button>
            <Button variant="secondary" v-if="pinCryptoMode === 'SM2'" @click="sm2DecryptPIN" class="justify-center">SM2解密</Button>
          </div>
          <Button variant="tool" block @click="parsePINBlock" class="justify-center">解析 PIN</Button>
        </Card>
      </div>

      <div class="sym-side">
        <Card title="PIN Block 结果">
          <ResultArea
            :modelValue="pinResult.block"
            :error="pinResult.error"
            :success="pinResult.success"
            label="PIN Block"
            copyable
          />
        </Card>
        <Card title="加/解密结果">
          <ResultArea
            :modelValue="pinCrypto.data"
            :error="pinCrypto.error"
            :success="pinCrypto.success"
            label="加/解密结果"
            copyable
          />
        </Card>
        <Card title="解析的 PIN">
          <ResultArea
            :modelValue="pinParse.pin"
            :error="pinParse.error"
            :success="pinParse.success"
            label="解析的 PIN"
            copyable
          />
        </Card>
        <Card title="算法原理">
          <div class="space-y-2 text-sm leading-5" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="card">
              <p class="card-title text-violet-400 text-[13px]">ISO-0</p>
              <p class="text-[13px]">把 PIN 字段和 PAN 右侧 12 位做异或，属于最常见的卡联机 PIN Block 组织方式。</p>
            </div>
            <div class="card">
              <p class="card-title text-emerald-400 text-[13px]">ISO-3</p>
              <p class="text-[13px]">在填充区引入随机值，结构和 ISO-0 类似，但更适合需要随机掩码的场景。</p>
            </div>
            <div class="card">
              <p class="card-title text-orange-300 text-[13px]">使用提醒</p>
              <p class="text-[13px]">生成、加解密、解析 PIN Block 时，PIN 长度、PAN 截取规则和密钥算法必须保持一致。</p>
            </div>
          </div>
        </Card>
      </div>
    </div>

    <!-- CVV / PVV -->
    <div v-if="activeTab === 'cvv'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <div class="card space-y-2">
          <p class="card-title">CVV / CVC / CVN / CSC</p>
          <div class="relative">
            <CryptoPanel v-model="cvv.cvk" label="CVK (Hex)" type="input" placeholder="32/48位..." />
            <button @click="genCVK" class="absolute right-8 top-1/2 -translate-y-1/2 ck-mini-trigger">⚡</button>
          </div>
          <input v-model="cvv.pan" class="input font-mono" placeholder="PAN" />
          <div class="grid grid-cols-2 gap-2">
            <input v-model="cvv.exp" class="input font-mono" placeholder="有效期 YYMM" />
            <input v-model="cvv.service" class="input font-mono" placeholder="服务代码" />
          </div>
          <div class="grid grid-cols-3 gap-2">
            <Dropdown
              v-model="cvv.length"
              :options="[
                { value: '3', label: '3位' },
                { value: '4', label: '4位' }
              ]"
            />
            <button @click="doCVV" class="btn-success col-span-2 justify-center">计算 CVV</button>
          </div>
        </div>

        <div class="card space-y-2">
          <p class="card-title">PVV (Visa PIN Verification)</p>
          <div class="relative">
            <CryptoPanel v-model="pvv.pvk" label="PVK (Hex)" type="input" placeholder="32/48位..." />
            <button @click="genPVK" class="absolute right-8 top-1/2 -translate-y-1/2 ck-mini-trigger">⚡</button>
          </div>
          <div class="grid grid-cols-3 gap-2">
            <input v-model="pvv.pvki" class="input font-mono" placeholder="PVKI" />
            <input v-model="pvv.pin" class="input font-mono" placeholder="PIN" />
            <input v-model="pvv.pan11" class="input font-mono" placeholder="PAN11" />
          </div>
          <button @click="doPVV" class="btn-warning w-full justify-center">计算 PVV</button>
        </div>
      </div>

      <div class="sym-side">
        <div class="card">
          <CryptoPanel v-model="cvvResult.cvv" label="CVV 结果" type="result" :success="cvvResult.success" copyable compact />
          <div v-if="cvvResult.error" class="mt-1 text-xs text-red-400">{{ cvvResult.error }}</div>
        </div>
        <div class="card">
          <CryptoPanel v-model="pvvResult.pvv" label="PVV 结果" type="result" :success="pvvResult.success" copyable compact />
          <div v-if="pvvResult.error" class="mt-1 text-xs text-red-400">{{ pvvResult.error }}</div>
        </div>
        <div class="card">
          <p class="card-title">算法原理</p>
          <div class="space-y-2 text-sm leading-5" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="card">
              <p class="card-title text-violet-400 text-[13px]">CVV / CVC</p>
              <p class="text-[13px]">将卡号、有效期和服务代码组织后做 3DES 运算，再转换成十进制校验值，用于卡面校验。</p>
            </div>
            <div class="card">
              <p class="card-title text-emerald-400 text-[13px]">PVV</p>
              <p class="text-[13px]">把 PVKI、PIN 和 PAN11 组合后做 3DES，再映射成十进制口令校验值，用于 PIN 验证体系。</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Key Diversification -->
    <div v-if="activeTab === 'kdv'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <div class="card space-y-2">
          <p class="card-title">EMV UDK 分散</p>
          <div class="relative">
            <CryptoPanel v-model="udk.mdk" label="MDK (Hex)" type="input" placeholder="32/48位..." />
            <button @click="genMDK" class="absolute right-8 top-1/2 -translate-y-1/2 ck-mini-trigger">⚡</button>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <input v-model="udk.pan" class="input font-mono" placeholder="PAN" />
            <input v-model="udk.psn" class="input font-mono" placeholder="PSN (2位)" />
          </div>
          <button @click="doUDK" class="btn-success w-full justify-center">分散计算</button>
        </div>

        <div class="card space-y-2">
          <p class="card-title">Double One Way (DOW)</p>
          <div class="relative">
            <CryptoPanel v-model="dow.key" label="Key (Hex)" type="input" placeholder="32/48位..." />
            <button @click="genDOWKey" class="absolute right-8 top-1/2 -translate-y-1/2 ck-mini-trigger">⚡</button>
          </div>
          <div class="relative">
            <CryptoPanel v-model="dow.data" label="Data (Hex)" type="input" placeholder="16位Hex..." />
            <button @click="genDOWData" class="absolute right-8 top-1/2 -translate-y-1/2 ck-mini-trigger">⚡</button>
          </div>
          <button @click="doDOW" class="btn-warning w-full justify-center">计算 DOW</button>
        </div>

        <div class="card space-y-2">
          <p class="card-title">SM4 UDK 分散</p>
          <div class="relative">
            <CryptoPanel v-model="sm4udk.mdk" label="SM4 MDK (Hex)" type="input" placeholder="32位..." />
            <button @click="genSM4MDK" class="absolute right-8 top-1/2 -translate-y-1/2 ck-mini-trigger">⚡</button>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <input v-model="sm4udk.pan" class="input font-mono" placeholder="PAN" />
            <input v-model="sm4udk.psn" class="input font-mono" placeholder="PSN" />
          </div>
          <button @click="doSM4UDK" class="btn-success w-full justify-center">SM4分散计算</button>
        </div>
      </div>

      <div class="sym-side">
        <div class="card">
          <CryptoPanel v-model="udkResult.udk" label="UDK (Hex)" type="result" :success="udkResult.success" copyable compact />
          <div v-if="udkResult.left" class="mt-1 text-[10px] text-emerald-400">L: {{ udkResult.left }} R: {{ udkResult.right }}</div>
          <div v-if="udkResult.error" class="mt-1 text-xs text-red-400">{{ udkResult.error }}</div>
        </div>
        <div class="card">
          <CryptoPanel v-model="dowResult.out" label="DOW (Hex)" type="result" :success="dowResult.success" copyable compact />
          <div v-if="dowResult.left" class="mt-1 text-[10px] text-emerald-400">L: {{ dowResult.left }} R: {{ dowResult.right }}</div>
          <div v-if="dowResult.error" class="mt-1 text-xs text-red-400">{{ dowResult.error }}</div>
        </div>
        <div class="card">
          <CryptoPanel v-model="sm4udkResult.udk" label="SM4 UDK (Hex)" type="result" :success="sm4udkResult.success" copyable compact />
          <div v-if="sm4udkResult.left" class="mt-1 text-[10px] text-emerald-400">L: {{ sm4udkResult.left }} R: {{ sm4udkResult.right }}</div>
          <div v-if="sm4udkResult.error" class="mt-1 text-xs text-red-400">{{ sm4udkResult.error }}</div>
        </div>
        <div class="card">
          <p class="card-title">算法原理</p>
          <div class="space-y-2 text-sm leading-5" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="card">
              <p class="card-title text-violet-400 text-[13px]">UDK / DOW</p>
              <p class="text-[13px]">按 PAN、PSN 或业务数据做一次或多次派生运算，把主密钥转换成设备级、卡级或会话级密钥。</p>
            </div>
            <div class="card">
              <p class="card-title text-orange-300 text-[13px]">SM4 UDK</p>
              <p class="text-[13px]">沿用 UDK 思路，但将底层分组算法替换为 SM4，适合国密合规体系中的分散密钥计算。</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- EMV -->
    <div v-if="activeTab === 'emv'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <div class="card space-y-2">
          <p class="card-title">ARQC / AC / Script MAC</p>
          <div class="relative">
            <CryptoPanel v-model="emv.key" label="Session Key (Hex)" type="input" placeholder="32/48位..." />
            <button @click="genSessionKey" class="absolute right-8 top-1/2 -translate-y-1/2 ck-mini-trigger">⚡</button>
          </div>
          <CryptoPanel v-model="emv.data" label="CDOL/Script (Hex)" type="textarea" :rows="3" clearable />
          <div class="flex gap-2">
            <Dropdown
              v-model="emv.padding"
              :options="[
                { value: 'ISO9797-1-P2', label: 'P2' },
                { value: 'ISO9797-1-P1', label: 'P1' }
              ]"
              class="flex-1"
            />
            <button @click="doARQC" class="btn-success justify-center shrink-0">计算 AC</button>
          </div>
        </div>

        <div class="card space-y-2">
          <p class="card-title">金融数据加密</p>
          <Dropdown
            v-model="cryptoMode"
            :options="[
              { value: '3DES', label: '3DES' },
              { value: 'SM4', label: 'SM4' }
            ]"
          />
          <div class="relative">
            <CryptoPanel v-if="cryptoMode === '3DES'" v-model="tdes.key" label="Key (Hex)" type="input" placeholder="32/48位..." />
            <CryptoPanel v-if="cryptoMode === 'SM4'" v-model="sm4crypto.key" label="SM4 Key (Hex)" type="input" placeholder="32位..." />
            <button @click="genCryptoKey" class="absolute right-8 top-1/2 -translate-y-1/2 ck-mini-trigger">⚡</button>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <Dropdown
              v-model="tdes.mode"
              :options="[
                { value: 'ECB', label: 'ECB' },
                { value: 'CBC', label: 'CBC' }
              ]"
            />
            <Dropdown
              v-model="tdes.padding"
              :options="[
                { value: 'ISO9797-1-P2', label: 'P2' },
                { value: 'ISO9797-1-P1', label: 'P1' }
              ]"
            />
          </div>
          <CryptoPanel v-if="tdes.mode === 'CBC'" v-model="tdes.iv" label="IV (Hex)" type="input" placeholder="16/32位..." />
          <CryptoPanel v-model="tdes.data" label="数据 (Hex)" type="textarea" :rows="3" clearable />
          <div class="grid grid-cols-2 gap-2">
            <button @click="doEncrypt" class="btn-success justify-center">加密</button>
            <button @click="doDecrypt" class="btn-warning justify-center">解密</button>
          </div>
        </div>
      </div>

      <div class="sym-side">
        <div class="card">
          <CryptoPanel v-model="emvResult.data" label="ARQC/AC (Hex)" type="result" :success="emvResult.success" copyable compact />
          <div v-if="emvResult.error" class="mt-1 text-xs text-red-400">{{ emvResult.error }}</div>
        </div>
        <div class="card">
          <CryptoPanel v-model="cryptoResult.data" label="加密结果 (Hex)" type="result" :success="cryptoResult.success" copyable compact />
          <div v-if="cryptoResult.extra" class="mt-1 text-[10px] text-emerald-400">IV: {{ cryptoResult.extra }}</div>
          <div v-if="cryptoResult.error" class="mt-1 text-xs text-red-400">{{ cryptoResult.error }}</div>
        </div>
        <div class="card">
          <p class="card-title">算法原理</p>
          <div class="space-y-2 text-sm leading-5" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="card">
              <p class="card-title text-violet-400 text-[13px]">ARQC / AC</p>
              <p class="text-[13px]">使用会话密钥对交易数据做 MAC 计算，结果通常用于联机交易认证或发卡行风险控制。</p>
            </div>
            <div class="card">
              <p class="card-title text-orange-300 text-[13px]">3DES / SM4</p>
              <p class="text-[13px]">金融数据加密既可能走传统 3DES，也可能走国密 SM4，关键在于模式、填充和 IV 管理保持一致。</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { FingerprintIcon } from 'lucide-vue-next'
import { storeToRefs } from 'pinia'
import Card from '../components/Card.vue'
import Input from '../components/Input.vue'
import Button from '../components/Button.vue'
import ResultArea from '../components/ResultArea.vue'
import AlgorithmDrawer from '../components/AlgorithmDrawer.vue'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import Dropdown from '../components/Dropdown.vue'
import { RetailMAC, SM4MAC, SM4CMAC, GeneratePINBlock, ParsePINBlock, EncryptPINBlock, DecryptPINBlock, ComputePVV, ComputeCVV, DeriveEMVUDK, DoubleOneWay, DeriveSM4UDK, ComputeARQC, TDESEncrypt, TDESDecrypt, SM4EncryptFinance, SM4DecryptFinance, SM2EncryptPIN, SM2DecryptPIN, SM4EncryptPIN, SM4DecryptPIN, SM2GenerateKey } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'mac', label: '卡片MAC' },
  { id: 'pin', label: 'PIN' },
  { id: 'cvv', label: 'CVV/PVV' },
  { id: 'kdv', label: '分散/密钥' },
  { id: 'emv', label: 'EMV' },
]
const activeTab = ref('mac')

const showPrinciple = ref(false)
const principles = {
  mac: {
    title: '金融数据密码原理',
    content: '设计目标: 为金融交易提供数据完整性和身份认证。\n核心算法:\n• Retail MAC: 基于 3DES 的传统银行卡消息认证码。\n• SM4-CBC-MAC: 国密 SM4 算法的 CBC 模式消息认证码。\n• SM4-CMAC: 基于子密钥派生的分组认证码，结构更规范。\n应用场景:\n• 银行卡报文认证 (ARQC/TC)\n• 交易数据完整性校验\n• 国密金融系统安全认证'
  }
}
const currentPrinciple = computed(() => principles[activeTab.value] || principles['mac'])

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

const retail = reactive({ key: '', data: '', padding: 'ISO9797-1-P2' })
const retailResult = reactive({ data: '', error: '', success: null })
async function doRetailMAC() {
  const r = await RetailMAC(retail)
  retailResult.data = r.data; retailResult.error = r.error; retailResult.success = r.success
}

const sm4mac = reactive({ key: '', data: '', padding: 'ISO9797-1-P2' })
const sm4macResult = reactive({ data: '', error: '', success: null })
async function doSM4MAC() {
  const r = await SM4MAC(sm4mac)
  sm4macResult.data = r.data; sm4macResult.error = r.error; sm4macResult.success = r.success
}

const sm4cmac = reactive({ key: '', data: '', padding: 'ISO9797-1-P2' })
const sm4cmacResult = reactive({ data: '', error: '', success: null })
async function doSM4CMAC() {
  const r = await SM4CMAC(sm4cmac)
  sm4cmacResult.data = r.data; sm4cmacResult.error = r.error; sm4cmacResult.success = r.success
}

const pin = reactive({ format: 'ISO-0', pin: '', pan: '', random: '', key: '', block: '' })
const pinCryptoMode = ref('3DES')
const pinResult = reactive({ block: '', random: '', error: '', success: null })
const pinCrypto = reactive({ data: '', error: '', success: null })
const pinParse = reactive({ pin: '', error: '', success: null })

async function genPINBlock() {
  const r = await GeneratePINBlock(pin)
  pinResult.block = r.block; pinResult.random = r.random; pinResult.error = r.error; pinResult.success = r.success
  if (r.block) pin.block = r.block
}
async function encryptPINBlock() {
  const r = await EncryptPINBlock({ key: pin.key, block: pin.block })
  pinCrypto.data = r.data; pinCrypto.error = r.error; pinCrypto.success = r.success
}
async function decryptPINBlock() {
  const r = await DecryptPINBlock({ key: pin.key, block: pin.block })
  pinCrypto.data = r.data; pinCrypto.error = r.error; pinCrypto.success = r.success
}
async function parsePINBlock() {
  const r = await ParsePINBlock({ format: pin.format, block: pin.block, pan: pin.pan })
  pinParse.pin = r.pin; pinParse.error = r.error; pinParse.success = r.success
}
function genPINKey() {
  const len = pinCryptoMode.value === 'SM4' ? 16 : 24
  const b = new Uint8Array(len); crypto.getRandomValues(b)
  pin.key = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}
async function genSM2Key() {
  const r = await SM2GenerateKey()
  if (r.PrivHex) {
    sm2pin.key = r.PrivHex
  } else if (r.PubHex) {
    sm2pin.key = r.PubHex
  }
}
async function sm4EncryptPIN() {
  const r = await SM4EncryptPIN({ key: pin.key, block: pin.block })
  pinCrypto.data = r.data; pinCrypto.error = r.error; pinCrypto.success = r.success
}
async function sm4DecryptPIN() {
  const r = await SM4DecryptPIN({ key: pin.key, block: pin.block })
  pinCrypto.data = r.data; pinCrypto.error = r.error; pinCrypto.success = r.success
}
async function sm2EncryptPIN() {
  const r = await SM2EncryptPIN({ key: sm2pin.key, block: pin.block })
  pinCrypto.data = r.data; pinCrypto.error = r.error; pinCrypto.success = r.success
}
async function sm2DecryptPIN() {
  const r = await SM2DecryptPIN({ key: sm2pin.key, block: pin.block })
  pinCrypto.data = r.data; pinCrypto.error = r.error; pinCrypto.success = r.success
}

const sm2pin = reactive({ key: '', block: '' })

const cvv = reactive({ cvk: '', pan: '', exp: '', service: '', decTable: '', length: 3 })
const cvvResult = reactive({ cvv: '', error: '', success: null })
async function doCVV() {
  const r = await ComputeCVV(cvv)
  cvvResult.cvv = r.cvv; cvvResult.error = r.error; cvvResult.success = r.success
}
function genCVK() {
  const b = new Uint8Array(16); crypto.getRandomValues(b)
  cvv.cvk = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

const pvv = reactive({ pvk: '', pvki: '', pin: '', pan11: '', decTable: '' })
const pvvResult = reactive({ pvv: '', error: '', success: null })
async function doPVV() {
  const r = await ComputePVV(pvv)
  pvvResult.pvv = r.pvv; pvvResult.error = r.error; pvvResult.success = r.success
}
function genPVK() {
  const b = new Uint8Array(16); crypto.getRandomValues(b)
  pvv.pvk = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

const udk = reactive({ mdk: '', pan: '', psn: '' })
const udkResult = reactive({ udk: '', left: '', right: '', error: '', success: null })
async function doUDK() {
  const r = await DeriveEMVUDK(udk)
  udkResult.udk = r.udk; udkResult.left = r.left; udkResult.right = r.right; udkResult.error = r.error; udkResult.success = r.success
}
function genMDK() {
  const b = new Uint8Array(16); crypto.getRandomValues(b)
  udk.mdk = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

const dow = reactive({ key: '', data: '' })
const dowResult = reactive({ out: '', left: '', right: '', error: '', success: null })
async function doDOW() {
  const r = await DoubleOneWay(dow)
  dowResult.out = r.out; dowResult.left = r.left; dowResult.right = r.right; dowResult.error = r.error; dowResult.success = r.success
}
function genDOWKey() {
  const b = new Uint8Array(16); crypto.getRandomValues(b)
  dow.key = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}
function genDOWData() {
  const b = new Uint8Array(8); crypto.getRandomValues(b)
  dow.data = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

const sm4udk = reactive({ mdk: '', pan: '', psn: '' })
const sm4udkResult = reactive({ udk: '', left: '', right: '', error: '', success: null })
async function doSM4UDK() {
  const r = await DeriveSM4UDK(sm4udk)
  sm4udkResult.udk = r.udk; sm4udkResult.left = r.left; sm4udkResult.right = r.right; sm4udkResult.error = r.error; sm4udkResult.success = r.success
}
function genSM4MDK() {
  const b = new Uint8Array(16); crypto.getRandomValues(b)
  sm4udk.mdk = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

const emv = reactive({ key: '', data: '', padding: 'ISO9797-1-P2' })
const emvResult = reactive({ data: '', error: '', success: null })
async function doARQC() {
  const r = await ComputeARQC(emv)
  emvResult.data = r.data; emvResult.error = r.error; emvResult.success = r.success
}
function genSessionKey() {
  const b = new Uint8Array(16); crypto.getRandomValues(b)
  emv.key = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

const cryptoMode = ref('3DES')
const tdes = reactive({ key: '', data: '', mode: 'ECB', iv: '', padding: 'ISO9797-1-P2' })
const sm4crypto = reactive({ key: '', data: '', mode: 'ECB', iv: '', padding: 'ISO9797-1-P2' })
const cryptoResult = reactive({ data: '', error: '', success: null, extra: '' })
async function doEncrypt() {
  if (cryptoMode.value === '3DES') {
    const r = await TDESEncrypt(tdes)
    cryptoResult.data = r.data; cryptoResult.error = r.error; cryptoResult.success = r.success; cryptoResult.extra = r.extra
  } else {
    const r = await SM4EncryptFinance({ key: sm4crypto.key, data: tdes.data, mode: tdes.mode, iv: tdes.iv, padding: tdes.padding })
    cryptoResult.data = r.data; cryptoResult.error = r.error; cryptoResult.success = r.success; cryptoResult.extra = r.extra
  }
}
async function doDecrypt() {
  if (cryptoMode.value === '3DES') {
    const r = await TDESDecrypt(tdes)
    cryptoResult.data = r.data; cryptoResult.error = r.error; cryptoResult.success = r.success; cryptoResult.extra = ''
  } else {
    const r = await SM4DecryptFinance({ key: sm4crypto.key, data: tdes.data, mode: tdes.mode, iv: tdes.iv, padding: tdes.padding })
    cryptoResult.data = r.data; cryptoResult.error = r.error; cryptoResult.success = r.success; cryptoResult.extra = ''
  }
}
function genCryptoKey() {
  const len = cryptoMode.value === 'SM4' ? 16 : 24
  const b = new Uint8Array(len); crypto.getRandomValues(b)
  if (cryptoMode.value === 'SM4') {
    sm4crypto.key = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
  } else {
    tdes.key = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
  }
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
