<template>
  <PageLayout title="金融数据密码" subtitle="磁条 / IC卡 MAC · PIN · CVV/PVV · 分散/密钥 · EMV"
              icon-bg="bg-indigo-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <ShieldIcon class="w-4 h-4 text-indigo-400" />
    </template>

    <!-- MAC -->
    <div v-if="activeTab === 'mac'" class="grid grid-cols-2 gap-3 animate-fade-in">
      <div class="space-y-2">
        <div class="ck-card space-y-2">
          <p class="ck-section-title">3DES Retail MAC</p>
          <CryptoPanel v-model="retail.key" label="密钥 (Hex)" type="input" placeholder="K1K2 或 K1K2K3..." /> />
          <CryptoPanel v-model="retail.data" label="数据 (Hex)" type="textarea" :rows="3" clearable /> />
          <div class="flex gap-2">
            <select v-model="retail.padding" class="ck-select flex-1">
              <option value="ISO9797-1-P2">P2 (0x80...)</option>
              <option value="ISO9797-1-P1">P1 (0x00...)</option>
            </select>
            <button @click="doRetailMAC" class="ck-btn-primary px-3">计算 MAC</button>
          </div>
        </div>

        <div class="ck-card space-y-2">
          <p class="ck-section-title">SM4-CBC-MAC</p>
          <CryptoPanel v-model="sm4mac.key" label="密钥 (Hex)" type="input" placeholder="32位Hex..." /> />
          <CryptoPanel v-model="sm4mac.data" label="数据 (Hex)" type="textarea" :rows="3" clearable /> />
          <div class="flex gap-2">
            <select v-model="sm4mac.padding" class="ck-select flex-1">
              <option value="ISO9797-1-P2">P2 (0x80...)</option>
              <option value="ISO9797-1-P1">P1</option>
            </select>
            <button @click="doSM4MAC" class="ck-btn-secondary px-3">SM4-CBC-MAC</button>
          </div>
        </div>

        <div class="ck-card space-y-2">
          <p class="ck-section-title">SM4-CMAC</p>
          <CryptoPanel v-model="sm4cmac.key" label="密钥 (Hex)" type="input" placeholder="32位Hex..." /> />
          <CryptoPanel v-model="sm4cmac.data" label="数据 (Hex)" type="textarea" :rows="3" clearable /> />
          <div class="flex gap-2">
            <select v-model="sm4cmac.padding" class="ck-select flex-1">
              <option value="ISO9797-1-P2">P2 (0x80...)</option>
              <option value="ISO9797-1-P1">P1</option>
            </select>
            <button @click="doSM4CMAC" class="ck-btn-success px-3">SM4-CMAC</button>
          </div>
        </div>
      </div>

      <div class="space-y-2">
        <div class="ck-card">
          <CryptoPanel v-model="retailResult.data" label="Retail MAC" type="result" :success="retailResult.success" copyable compact />
          <div v-if="retailResult.error" class="mt-1 text-xs text-red-400">{{ retailResult.error }}</div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="sm4macResult.data" label="SM4-CBC-MAC" type="result" :success="sm4macResult.success" copyable compact />
          <div v-if="sm4macResult.error" class="mt-1 text-xs text-red-400">{{ sm4macResult.error }}</div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="sm4cmacResult.data" label="SM4-CMAC" type="result" :success="sm4cmacResult.success" copyable compact />
          <div v-if="sm4cmacResult.error" class="mt-1 text-xs text-red-400">{{ sm4cmacResult.error }}</div>
        </div>
        <div class="ck-card">
          <p class="ck-section-title text-xs">算法原理</p>
          <div class="text-[10px] space-y-1" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-1.5 rounded border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <span class="text-violet-400 font-medium">Retail MAC</span>: K1 CBC-MAC → K2 解密 → K3 加密
            </div>
            <div class="p-1.5 rounded border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <span class="text-emerald-400 font-medium">SM4-CBC-MAC</span>: IV=0 → CBC → 取最后密文
            </div>
            <div class="p-1.5 rounded border border-amber-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <span class="text-amber-400 font-medium">SM4-CMAC</span>: 子密钥K1/K2 → CBC-MAC
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- PIN -->
    <div v-if="activeTab === 'pin'" class="grid grid-cols-2 gap-3 animate-fade-in">
      <div class="space-y-2">
        <div class="ck-card space-y-2">
          <p class="ck-section-title">PIN Block 生成</p>
          <select v-model="pin.format" class="ck-select">
            <option value="ISO-0">ISO-0 (PIN ^ PAN)</option>
            <option value="ISO-3">ISO-3 (随机填充)</option>
          </select>
          <div class="grid grid-cols-2 gap-2">
            <input v-model="pin.pin" class="ck-input font-mono" placeholder="PIN (4-12位)" />
            <input v-model="pin.pan" class="ck-input font-mono" placeholder="PAN" />
          </div>
          <button @click="genPINBlock" class="ck-btn-primary w-full text-xs py-1.5">生成 PIN Block</button>
        </div>

        <div class="ck-card space-y-2">
          <p class="ck-section-title">PIN Block 加/解密</p>
          <select v-model="pinCryptoMode" class="ck-select">
            <option value="3DES">3DES</option>
            <option value="SM4">SM4</option>
            <option value="SM2">SM2</option>
          </select>
          <div class="relative">
            <CryptoPanel v-if="pinCryptoMode !== 'SM2'" v-model="pin.key" label="密钥 (Hex)" type="input" :placeholder="pinCryptoMode === 'SM4' ? '32位...' : '32/48位...'" /> />
            <CryptoPanel v-if="pinCryptoMode === 'SM2'" v-model="sm2pin.key" label="SM2密钥 (Hex)" type="input" placeholder="公钥/私钥Hex..." /> />
            <button v-if="pinCryptoMode !== 'SM2'" @click="genPINKey" class="absolute right-8 top-1/2 -translate-y-1/2 text-xs text-violet-400">⚡</button>
            <button v-if="pinCryptoMode === 'SM2'" @click="genSM2Key" class="absolute right-8 top-1/2 -translate-y-1/2 text-xs text-violet-400">⚡</button>
          </div>
          <CryptoPanel v-model="pin.block" label="PIN Block (Hex)" type="input" placeholder="8字节..." /> />
          <div class="grid grid-cols-2 gap-2">
            <button v-if="pinCryptoMode === '3DES'" @click="encryptPINBlock" class="ck-btn-primary text-xs py-1.5">加密</button>
            <button v-if="pinCryptoMode === 'SM4'" @click="sm4EncryptPIN" class="ck-btn-primary text-xs py-1.5">SM4加密</button>
            <button v-if="pinCryptoMode === 'SM2'" @click="sm2EncryptPIN" class="ck-btn-primary text-xs py-1.5">SM2加密</button>
            <button v-if="pinCryptoMode === '3DES'" @click="decryptPINBlock" class="ck-btn-secondary text-xs py-1.5">解密</button>
            <button v-if="pinCryptoMode === 'SM4'" @click="sm4DecryptPIN" class="ck-btn-secondary text-xs py-1.5">SM4解密</button>
            <button v-if="pinCryptoMode === 'SM2'" @click="sm2DecryptPIN" class="ck-btn-secondary text-xs py-1.5">SM2解密</button>
          </div>
          <button @click="parsePINBlock" class="ck-btn-success w-full text-xs py-1.5">解析 PIN</button>
        </div>
      </div>

      <div class="space-y-2">
        <div class="ck-card">
          <CryptoPanel v-model="pinResult.block" label="PIN Block" type="result" :success="pinResult.success" copyable compact />
          <div v-if="pinResult.error" class="mt-1 text-xs text-red-400">{{ pinResult.error }}</div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="pinCrypto.data" label="加/解密结果" type="result" :success="pinCrypto.success" copyable compact />
          <div v-if="pinCrypto.error" class="mt-1 text-xs text-red-400">{{ pinCrypto.error }}</div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="pinParse.pin" label="解析的 PIN" type="result" :success="pinParse.success" copyable compact />
          <div v-if="pinParse.error" class="mt-1 text-xs text-red-400">{{ pinParse.error }}</div>
        </div>
        <div class="ck-card">
          <p class="ck-section-title text-xs">算法原理</p>
          <div class="text-[10px] space-y-1" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-1.5 rounded border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <span class="text-violet-400 font-medium">ISO-0</span>: P1||L||PIN||PADDING ⊕ P2||PAN(右12位)
            </div>
            <div class="p-1.5 rounded border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <span class="text-emerald-400 font-medium">ISO-3</span>: P3||L||PIN||RANDOM ⊕ P2||PAN
            </div>
            <div class="p-1.5 rounded border border-amber-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <span class="text-amber-400 font-medium">示例</span>: PIN=1234, PAN=6222... → Field: 041234FFFFFFFFF ⊕ 000002...
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- CVV / PVV -->
    <div v-if="activeTab === 'cvv'" class="grid grid-cols-2 gap-3 animate-fade-in">
      <div class="space-y-2">
        <div class="ck-card space-y-2">
          <p class="ck-section-title">CVV / CVC / CVN / CSC</p>
          <div class="relative">
            <CryptoPanel v-model="cvv.cvk" label="CVK (Hex)" type="input" placeholder="32/48位..." /> />
            <button @click="genCVK" class="absolute right-8 top-1/2 -translate-y-1/2 text-xs text-violet-400">⚡</button>
          </div>
          <input v-model="cvv.pan" class="ck-input font-mono" placeholder="PAN" />
          <div class="grid grid-cols-2 gap-2">
            <input v-model="cvv.exp" class="ck-input font-mono" placeholder="有效期 YYMM" />
            <input v-model="cvv.service" class="ck-input font-mono" placeholder="服务代码" />
          </div>
          <div class="grid grid-cols-3 gap-2">
            <select v-model.number="cvv.length" class="ck-select">
              <option :value="3">3位</option>
              <option :value="4">4位</option>
            </select>
            <button @click="doCVV" class="ck-btn-primary col-span-2 text-xs py-1.5">计算 CVV</button>
          </div>
        </div>

        <div class="ck-card space-y-2">
          <p class="ck-section-title">PVV (Visa PIN Verification)</p>
          <div class="relative">
            <CryptoPanel v-model="pvv.pvk" label="PVK (Hex)" type="input" placeholder="32/48位..." /> />
            <button @click="genPVK" class="absolute right-8 top-1/2 -translate-y-1/2 text-xs text-violet-400">⚡</button>
          </div>
          <div class="grid grid-cols-3 gap-2">
            <input v-model="pvv.pvki" class="ck-input font-mono" placeholder="PVKI" />
            <input v-model="pvv.pin" class="ck-input font-mono" placeholder="PIN" />
            <input v-model="pvv.pan11" class="ck-input font-mono" placeholder="PAN11" />
          </div>
          <button @click="doPVV" class="ck-btn-secondary w-full text-xs py-1.5">计算 PVV</button>
        </div>
      </div>

      <div class="space-y-2">
        <div class="ck-card">
          <CryptoPanel v-model="cvvResult.cvv" label="CVV 结果" type="result" :success="cvvResult.success" copyable compact />
          <div v-if="cvvResult.error" class="mt-1 text-xs text-red-400">{{ cvvResult.error }}</div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="pvvResult.pvv" label="PVV 结果" type="result" :success="pvvResult.success" copyable compact />
          <div v-if="pvvResult.error" class="mt-1 text-xs text-red-400">{{ pvvResult.error }}</div>
        </div>
        <div class="ck-card">
          <p class="ck-section-title text-xs">算法原理</p>
          <div class="text-[10px] space-y-1" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-1.5 rounded border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <span class="text-violet-400 font-medium">CVV</span>: PAN||Exp||Svc → BCD → 3DES ECB → XOR → 十进制化
            </div>
            <div class="p-1.5 rounded border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <span class="text-emerald-400 font-medium">PVV</span>: PVKI||PIN||PAN11 → BCD → 3DES → 十进制化表 → 取前4位
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Key Diversification -->
    <div v-if="activeTab === 'kdv'" class="grid grid-cols-2 gap-3 animate-fade-in">
      <div class="space-y-2">
        <div class="ck-card space-y-2">
          <p class="ck-section-title">EMV UDK 分散</p>
          <div class="relative">
            <CryptoPanel v-model="udk.mdk" label="MDK (Hex)" type="input" placeholder="32/48位..." /> />
            <button @click="genMDK" class="absolute right-8 top-1/2 -translate-y-1/2 text-xs text-violet-400">⚡</button>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <input v-model="udk.pan" class="ck-input font-mono" placeholder="PAN" />
            <input v-model="udk.psn" class="ck-input font-mono" placeholder="PSN (2位)" />
          </div>
          <button @click="doUDK" class="ck-btn-primary w-full text-xs py-1.5">分散计算</button>
        </div>

        <div class="ck-card space-y-2">
          <p class="ck-section-title">Double One Way (DOW)</p>
          <div class="relative">
            <CryptoPanel v-model="dow.key" label="Key (Hex)" type="input" placeholder="32/48位..." /> />
            <button @click="genDOWKey" class="absolute right-8 top-1/2 -translate-y-1/2 text-xs text-violet-400">⚡</button>
          </div>
          <div class="relative">
            <CryptoPanel v-model="dow.data" label="Data (Hex)" type="input" placeholder="16位Hex..." /> />
            <button @click="genDOWData" class="absolute right-8 top-1/2 -translate-y-1/2 text-xs text-violet-400">⚡</button>
          </div>
          <button @click="doDOW" class="ck-btn-secondary w-full text-xs py-1.5">计算 DOW</button>
        </div>

        <div class="ck-card space-y-2">
          <p class="ck-section-title">SM4 UDK 分散</p>
          <div class="relative">
            <CryptoPanel v-model="sm4udk.mdk" label="SM4 MDK (Hex)" type="input" placeholder="32位..." /> />
            <button @click="genSM4MDK" class="absolute right-8 top-1/2 -translate-y-1/2 text-xs text-violet-400">⚡</button>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <input v-model="sm4udk.pan" class="ck-input font-mono" placeholder="PAN" />
            <input v-model="sm4udk.psn" class="ck-input font-mono" placeholder="PSN" />
          </div>
          <button @click="doSM4UDK" class="ck-btn-success w-full text-xs py-1.5">SM4分散计算</button>
        </div>
      </div>

      <div class="space-y-2">
        <div class="ck-card">
          <CryptoPanel v-model="udkResult.udk" label="UDK (Hex)" type="result" :success="udkResult.success" copyable compact />
          <div v-if="udkResult.left" class="mt-1 text-[10px] text-emerald-400">L: {{ udkResult.left }} R: {{ udkResult.right }}</div>
          <div v-if="udkResult.error" class="mt-1 text-xs text-red-400">{{ udkResult.error }}</div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="dowResult.out" label="DOW (Hex)" type="result" :success="dowResult.success" copyable compact />
          <div v-if="dowResult.left" class="mt-1 text-[10px] text-emerald-400">L: {{ dowResult.left }} R: {{ dowResult.right }}</div>
          <div v-if="dowResult.error" class="mt-1 text-xs text-red-400">{{ dowResult.error }}</div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="sm4udkResult.udk" label="SM4 UDK (Hex)" type="result" :success="sm4udkResult.success" copyable compact />
          <div v-if="sm4udkResult.left" class="mt-1 text-[10px] text-emerald-400">L: {{ sm4udkResult.left }} R: {{ sm4udkResult.right }}</div>
          <div v-if="sm4udkResult.error" class="mt-1 text-xs text-red-400">{{ sm4udkResult.error }}</div>
        </div>
        <div class="ck-card">
          <p class="ck-section-title text-xs">算法原理</p>
          <div class="text-[10px] space-y-1" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-1.5 rounded border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <span class="text-violet-400 font-medium">UDK</span>: Left=Enc(MDK, PAN14||PSN||F), Right=Enc(MDK, XOR)
            </div>
            <div class="p-1.5 rounded border border-amber-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <span class="text-amber-400 font-medium">SM4 UDK</span>: 同UDK流程，使用SM4算法
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- EMV -->
    <div v-if="activeTab === 'emv'" class="grid grid-cols-2 gap-3 animate-fade-in">
      <div class="space-y-2">
        <div class="ck-card space-y-2">
          <p class="ck-section-title">ARQC / AC / Script MAC</p>
          <div class="relative">
            <CryptoPanel v-model="emv.key" label="Session Key (Hex)" type="input" placeholder="32/48位..." /> />
            <button @click="genSessionKey" class="absolute right-8 top-1/2 -translate-y-1/2 text-xs text-violet-400">⚡</button>
          </div>
          <CryptoPanel v-model="emv.data" label="CDOL/Script (Hex)" type="textarea" :rows="3" clearable /> />
          <div class="flex gap-2">
            <select v-model="emv.padding" class="ck-select flex-1">
              <option value="ISO9797-1-P2">P2</option>
              <option value="ISO9797-1-P1">P1</option>
            </select>
            <button @click="doARQC" class="ck-btn-primary px-3">计算 AC</button>
          </div>
        </div>

        <div class="ck-card space-y-2">
          <p class="ck-section-title">金融数据加密</p>
          <select v-model="cryptoMode" class="ck-select">
            <option value="3DES">3DES</option>
            <option value="SM4">SM4</option>
          </select>
          <div class="relative">
            <CryptoPanel v-if="cryptoMode === '3DES'" v-model="tdes.key" label="Key (Hex)" type="input" placeholder="32/48位..." /> />
            <CryptoPanel v-if="cryptoMode === 'SM4'" v-model="sm4crypto.key" label="SM4 Key (Hex)" type="input" placeholder="32位..." /> />
            <button @click="genCryptoKey" class="absolute right-8 top-1/2 -translate-y-1/2 text-xs text-violet-400">⚡</button>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <select v-model="tdes.mode" class="ck-select">
              <option>ECB</option>
              <option>CBC</option>
            </select>
            <select v-model="tdes.padding" class="ck-select">
              <option value="ISO9797-1-P2">P2</option>
              <option value="ISO9797-1-P1">P1</option>
            </select>
          </div>
          <CryptoPanel v-if="tdes.mode === 'CBC'" v-model="tdes.iv" label="IV (Hex)" type="input" placeholder="16/32位..." /> />
          <CryptoPanel v-model="tdes.data" label="数据 (Hex)" type="textarea" :rows="3" clearable /> />
          <div class="grid grid-cols-2 gap-2">
            <button @click="doEncrypt" class="ck-btn-primary text-xs py-1.5">加密</button>
            <button @click="doDecrypt" class="ck-btn-secondary text-xs py-1.5">解密</button>
          </div>
        </div>
      </div>

      <div class="space-y-2">
        <div class="ck-card">
          <CryptoPanel v-model="emvResult.data" label="ARQC/AC (Hex)" type="result" :success="emvResult.success" copyable compact />
          <div v-if="emvResult.error" class="mt-1 text-xs text-red-400">{{ emvResult.error }}</div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="cryptoResult.data" label="加密结果 (Hex)" type="result" :success="cryptoResult.success" copyable compact />
          <div v-if="cryptoResult.extra" class="mt-1 text-[10px] text-emerald-400">IV: {{ cryptoResult.extra }}</div>
          <div v-if="cryptoResult.error" class="mt-1 text-xs text-red-400">{{ cryptoResult.error }}</div>
        </div>
        <div class="ck-card">
          <p class="ck-section-title text-xs">算法原理</p>
          <div class="text-[10px] space-y-1" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-1.5 rounded border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <span class="text-violet-400 font-medium">ARQC/AC</span>: Retail MAC(Session Key, CDOL数据)
            </div>
            <div class="p-1.5 rounded border border-amber-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <span class="text-amber-400 font-medium">3DES</span>: 分组64位, 16/24字节密钥, ECB/CBC模式
            </div>
            <div class="p-1.5 rounded border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <span class="text-emerald-400 font-medium">SM4</span>: 分组128位, 16字节密钥, ECB/CBC模式
            </div>
          </div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { ShieldIcon, ShieldCheckIcon } from 'lucide-vue-next'
import { storeToRefs } from 'pinia'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
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
