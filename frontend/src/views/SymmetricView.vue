<template>
  <PageLayout title="对称算法" subtitle="AES · DES/3DES · ChaCha20 · 全模式支持"
              icon-bg="bg-blue-500/20"
              :tabs="tabs" :active-tab="activeTab"
              @tab-change="activeTab = $event">
    <template #icon>
      <LockIcon class="w-4 h-4 text-blue-400" />
    </template>

    <template #actions>
      <div class="flex gap-2">
        <Button variant="secondary" size="sm" @click="drawerOpen = true">
          <ShieldCheckIcon class="w-3.5 h-3.5" /> 算法原理
        </Button>
      </div>
    </template>

    <!-- Algorithm Principle Drawer -->
    <AlgorithmDrawer
      :is-open="drawerOpen"
      :title="currentPrinciple.title"
      :icon="ShieldCheckIcon"
      @close="drawerOpen = false"
    >
      <div v-for="(section, idx) in parsedPrinciples" :key="idx">
        <h4>{{ section.title }}</h4>
        <p v-for="(line, lIdx) in section.content" :key="lIdx" class="principle-line">
          {{ line }}
        </p>
      </div>
    </AlgorithmDrawer>

    <!-- AES Tab -->
    <div v-if="activeTab === 'aes'" class="sym-workbench animate-fade-in">
      <!-- Left: params -->
      <div class="space-y-3 sym-side">
        <Card title="算法参数">
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="input-label">密钥长度</label>
              <Dropdown 
                v-model="aes.keySize" 
                :options="keySizeOptions"
                placeholder="选择密钥长度"
              />
            </div>
            <div>
              <label class="input-label">加密模式</label>
              <Dropdown
                v-model="aes.mode"
                :options="[
                  { value: 'ECB', label: 'ECB' },
                  { value: 'CBC', label: 'CBC' },
                  { value: 'CFB', label: 'CFB' },
                  { value: 'OFB', label: 'OFB' },
                  { value: 'CTR', label: 'CTR' },
                  { value: 'GCM', label: 'GCM' },
                  { value: 'CCM', label: 'CCM' }
                ]"
              />
            </div>
            <div>
              <label class="input-label">填充方式</label>
              <Dropdown
                v-model="aes.padding"
                :options="[
                  { value: 'PKCS7', label: 'PKCS7' },
                  { value: 'Zero', label: 'Zero' },
                  { value: 'ISO10126', label: 'ISO10126' },
                  { value: 'NoPadding', label: 'NoPadding' }
                ]"
                :disabled="['CTR','GCM','CCM','CFB','OFB'].includes(aes.mode)"
              />
            </div>
            <div>
              <label class="input-label">输入格式</label>
              <Dropdown
                v-model="aes.inputFormat"
                :options="[
                  { value: 'text', label: '文本' },
                  { value: 'hex', label: 'Hex' }
                ]"
              />
            </div>
          </div>
        </Card>

        <Card title="密钥 & 参数">
          <div>
            <div class="flex items-center justify-between mb-1">
              <label class="input-label !mb-0">密钥 (hex)</label>
              <Button variant="tool" size="sm" @click="genKey">⚡ 生成</Button>
            </div>
            <InputWithBytes v-model="aes.key" placeholder="输入hex格式密钥..." />
            <div v-if="aesKeyHint" :class="['mt-1 text-xs', hintClass(aesKeyHint)]">{{ aesKeyHint }}</div>
          </div>
          <div v-if="!['ECB','GCM','CCM'].includes(aes.mode)">
            <div class="flex items-center justify-between mb-1">
              <label class="input-label !mb-0">IV (hex)</label>
              <Button variant="tool" size="sm" @click="genIV">⚡ 生成</Button>
            </div>
            <InputWithBytes v-model="aes.iv" placeholder="留空则自动生成..." />
            <div v-if="aesIVHint" :class="['mt-1 text-xs', hintClass(aesIVHint)]">{{ aesIVHint }}</div>
          </div>
          <div v-if="['GCM','CCM'].includes(aes.mode)">
            <div class="flex items-center justify-between mb-1">
              <label class="input-label !mb-0">Nonce (hex)</label>
              <Button variant="tool" size="sm" @click="genNonce">⚡ 生成</Button>
            </div>
            <InputWithBytes v-model="aes.nonce" placeholder="留空则自动生成..." />
            <div v-if="aesNonceHint" :class="['mt-1 text-xs', hintClass(aesNonceHint)]">{{ aesNonceHint }}</div>
            <div class="mt-2">
              <label class="input-label">AAD (可选, hex)</label>
              <InputWithBytes v-model="aes.aad" placeholder="附加认证数据..." />
              <div v-if="aesAADHint" :class="['mt-1 text-xs', hintClass(aesAADHint)]">{{ aesAADHint }}</div>
            </div>
          </div>
        </Card>
      </div>

      <!-- Middle: data + result -->
      <div class="sym-main">
        <Card class="flex-1 min-h-0 flex flex-col">
          <div class="mb-3">
            <label class="input-label">明文</label>
            <InputWithBytes 
              v-model="aes.plaintext" 
              :placeholder="aes.inputFormat === 'text' ? '输入明文...' : '输入hex格式数据...'"
              type="textarea"
              :rows="5"
              :is-hex="aes.inputFormat === 'hex'"
            />
            <div class="flex items-center justify-between mt-1">
              <div v-if="aesLenHint" :class="['text-xs', hintClass(aesLenHint)]">{{ aesLenHint }}</div>
            </div>
          </div>
          <div class="flex gap-2 shrink-0 mt-3">
            <Button variant="success" class="flex-1" @click="encrypt" :disabled="aesDisabled">
              <LockIcon class="w-3.5 h-3.5" /> 加密
            </Button>
            <Button variant="warning" class="flex-1" @click="decrypt" :disabled="aesDisabled">
              <UnlockIcon class="w-3.5 h-3.5" /> 解密
            </Button>
          </div>
        </Card>
        
        <ResultArea
          v-model="result.data"
          label="运算结果 (Hex)"
          :success="result.success"
          :error="result.error"
          copyable
        />
        
        <ResultExtra
          v-model="result.extra"
          :label="`${result.success && !result.error ? (aes.iv || aes.nonce ? '运算后' : '自动生成的') : '自动生成的'} ${['GCM','CCM'].includes(aes.mode) ? 'Nonce' : 'IV'}`"
        />
        
      </div>
    </div>

    <!-- SM4 Tab -->
    <div v-if="activeTab === 'sm4'" class="sym-workbench animate-fade-in">
      <div class="space-y-3 sym-side">
        <Card title="算法参数">
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="input-label">工作模式</label>
              <Dropdown
                v-model="sm4.mode"
                :options="[
                  { value: 'ECB', label: 'ECB' },
                  { value: 'CBC', label: 'CBC' },
                  { value: 'CFB', label: 'CFB' },
                  { value: 'OFB', label: 'OFB' },
                  { value: 'CTR', label: 'CTR' },
                  { value: 'GCM', label: 'GCM' }
                ]"
              />
            </div>
            <div>
              <label class="input-label">填充方式</label>
              <Dropdown
                v-model="sm4.padding"
                :options="[
                  { value: 'PKCS7', label: 'PKCS7' },
                  { value: 'Zero', label: 'Zero' },
                  { value: 'NoPadding', label: 'NoPadding' }
                ]"
                :disabled="sm4.mode === 'GCM'"
              />
            </div>
          </div>
        </Card>
        <Card title="密钥 & 参数">
          <div>
            <div class="flex justify-between mb-1">
              <label class="input-label !mb-0 text-orange-300">密钥 (Key / 16-byte Hex)</label>
              <Button variant="tool" size="sm" @click="genSM4Key">⚡ 随机生成</Button>
            </div>
            <InputWithBytes v-model="sm4.key" placeholder="输入 32 位 Hex..." />
          </div>
          <div v-if="sm4.mode !== 'ECB' && sm4.mode !== 'GCM'">
            <div class="flex justify-between mb-1">
              <label class="input-label !mb-0 text-cyan-400">初始化向量 (IV / 16-byte Hex)</label>
              <Button variant="tool" size="sm" @click="genSM4IV">⚡ 随机生成</Button>
            </div>
            <InputWithBytes v-model="sm4.iv" placeholder="输入 32 位 Hex..." />
          </div>
          <div v-if="sm4.mode === 'GCM'" class="space-y-3">
            <div>
              <div class="flex justify-between mb-1">
                <label class="input-label !mb-0 text-cyan-400">Nonce (12-byte Hex)</label>
                <Button variant="tool" size="sm" @click="genSM4Nonce">⚡ 随机生成</Button>
              </div>
              <InputWithBytes v-model="sm4.nonce" />
            </div>
            <div>
              <label class="input-label">附加认证数据 (AAD / 可选 Hex)</label>
              <InputWithBytes v-model="sm4.aad" />
            </div>
          </div>
        </Card>
      </div>
      <div class="sym-main">
        <Card class="flex-1 min-h-0 flex flex-col">
          <CryptoPanel v-model="sm4.data" label="数据 (Hex)" type="textarea" :rows="3" clearable />
          <div class="grid grid-cols-2 gap-2 shrink-0 mt-3">
            <Button variant="success" @click="doSM4Encrypt"><LockIcon class="w-3.5 h-3.5" /> 加密</Button>
            <Button variant="warning" @click="doSM4Decrypt"><UnlockIcon class="w-3.5 h-3.5" /> 解密</Button>
          </div>
        </Card>
        <ResultArea
          v-model="sm4Result.data"
          label="运算结果 (Hex)"
          :success="sm4Result.success"
          :error="sm4Result.error"
          copyable
        />
        <ResultExtra
          v-model="sm4Result.extra"
          :label="`${sm4.iv || sm4.nonce ? '运算后' : '自动生成的'} ${sm4.mode === 'GCM' ? 'Nonce' : 'IV'}`"
        />
      </div>
    </div>

    <!-- ZUC Tab -->
    <div v-if="activeTab === 'zuc'" class="sym-workbench animate-fade-in">
      <div class="space-y-3 sym-side">
        <Card title="算法参数">
          <div>
            <label class="input-label">算法版本</label>
            <Dropdown
              v-model="zuc.type"
              :options="[
                { value: 'ZUC-128', label: 'ZUC-128 (4G/LTE)' },
                { value: 'ZUC-256', label: 'ZUC-256 (5G 增强)' }
              ]"
            />
          </div>
        </Card>
        <Card title="密钥 & 参数">
          <div>
            <div class="flex justify-between mb-1">
              <label class="input-label !mb-0 text-orange-300">密钥 (Key / Hex)</label>
              <Button variant="tool" size="sm" @click="genZUCKey">⚡ 生成</Button>
            </div>
            <InputWithBytes v-model="zuc.key" :placeholder="zuc.type === 'ZUC-256' ? '64位 Hex' : '32位 Hex'" />
          </div>
          <div>
            <div class="flex justify-between mb-1">
              <label class="input-label !mb-0 text-cyan-400">向量 (IV / Hex)</label>
              <Button variant="tool" size="sm" @click="genZUCIV">⚡ 生成</Button>
            </div>
            <InputWithBytes v-model="zuc.iv" :placeholder="zuc.type === 'ZUC-256' ? '50位 Hex' : '32位 Hex'" />
          </div>
        </Card>
      </div>
      <div class="sym-main">
        <Card class="flex-1 min-h-0 flex flex-col">
          <CryptoPanel v-model="zuc.data" label="待加/解密数据 (Hex)" type="textarea" :rows="3" clearable />
          <Button variant="success" @click="doZUCEncrypt" class="w-full shrink-0 mt-3">
            <ZapIcon class="w-3.5 h-3.5" /> 执行 ZUC 变换
          </Button>
        </Card>
        <ResultArea
          v-model="zucResult.data"
          label="变换结果 (Hex)"
          :success="zucResult.success"
          :error="zucResult.error"
          copyable
        />
      </div>
    </div>

    <!-- Envelope Tab -->
    <div v-if="activeTab === 'envelope'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="加密 (制作数字信封)">
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="input-label">发送方私钥 (SM2)</label>
              <Input v-model="envelope.senderPriv" show-bytes class="font-mono text-xs" placeholder="64位Hex (32字节)" />
            </div>
            <div>
              <label class="input-label">接收方公钥 (SM2)</label>
              <Input v-model="envelope.receiverPub" show-bytes class="font-mono text-xs" placeholder="64位Hex (32字节)" />
            </div>
          </div>
          <div>
            <label class="input-label">待加密数据</label>
            <div class="relative">
              <textarea v-model="envelope.data" rows="3" class="input font-mono text-xs pb-7" placeholder="Hex 格式数据..."></textarea>
              <ByteBadge :model-value="envelope.data" />
            </div>
          </div>
          <Button variant="success" @click="makeEnvelope" class="w-full" :disabled="!envelope.senderPriv || !envelope.receiverPub || !envelope.data">
            <LockIcon class="w-3.5 h-3.5" /> 生成数字信封
          </Button>
          <div v-if="envelopeResult.error" class="text-xs text-red-400">{{ envelopeResult.error }}</div>
          <div v-if="envelopeResult.data">
            <label class="input-label !mb-0 text-emerald-400">数字信封结果</label>
            <div class="relative">
              <textarea readonly :value="envelopeResult.data" rows="4" class="result-area font-mono text-xs mt-1 pb-7"></textarea>
              <ByteBadge :model-value="envelopeResult.data" />
            </div>
          </div>
        </Card>

        <Card title="解密 (打开数字信封)">
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="input-label">接收方私钥 (SM2)</label>
              <Input v-model="envelope.receiverPriv" show-bytes class="font-mono text-xs" placeholder="64位Hex (32字节)" />
            </div>
            <div>
              <label class="input-label">发送方公钥 (SM2)</label>
              <Input v-model="envelope.senderPub" show-bytes class="font-mono text-xs" placeholder="64位Hex (32字节)" />
            </div>
          </div>
          <div>
            <label class="input-label">数字信封数据</label>
            <div class="relative">
              <textarea v-model="envelope.envelopeData" rows="4" class="input font-mono text-xs pb-7" placeholder="Hex 格式信封数据..."></textarea>
              <ByteBadge :model-value="envelope.envelopeData" />
            </div>
          </div>
          <Button variant="warning" @click="openEnvelope" class="w-full" :disabled="!envelope.receiverPriv || !envelope.senderPub || !envelope.envelopeData">
            <UnlockIcon class="w-3.5 h-3.5" /> 打开数字信封
          </Button>
          <div v-if="envelopeResult.error" class="text-xs text-red-400">{{ envelopeResult.error }}</div>
          <div v-if="envelopeResult.success && !envelopeResult.error">
            <label class="input-label !mb-0 text-emerald-400">解密结果</label>
            <textarea readonly :value="envelopeResult.data" rows="3" class="result-area font-mono text-xs mt-1"></textarea>
          </div>
        </Card>
      </div>
    </div>

    <!-- DES Tab -->
    <div v-if="activeTab === 'des'" class="sym-workbench animate-fade-in">
      <div class="space-y-3 sym-side">
        <Card title="算法参数">
          <div class="grid grid-cols-3 gap-3">
            <div>
              <label class="input-label">算法类型</label>
              <Dropdown
                v-model="des.type"
                :options="[
                  { value: 'DES', label: 'DES (56位)' },
                  { value: '3DES', label: '3DES (168位)' }
                ]"
              />
            </div>
            <div>
              <label class="input-label">加密模式</label>
              <Dropdown
                v-model="des.mode"
                :options="[
                  { value: 'ECB', label: 'ECB' },
                  { value: 'CBC', label: 'CBC' },
                  { value: 'CFB', label: 'CFB' },
                  { value: 'OFB', label: 'OFB' },
                  { value: 'CTR', label: 'CTR' }
                ]"
              />
            </div>
            <div>
              <label class="input-label">填充方式</label>
              <Dropdown
                v-model="des.padding"
                :options="[
                  { value: 'PKCS7', label: 'PKCS7' },
                  { value: 'Zero', label: 'Zero' },
                  { value: 'NoPadding', label: 'NoPadding' }
                ]"
              />
            </div>
          </div>
        </Card>
        <Card title="密钥 & 参数">
          <div>
            <div class="flex justify-between mb-1">
              <label class="input-label !mb-0">密钥 (hex)</label>
              <Button variant="tool" size="sm" @click="genDesKey">⚡ 生成</Button>
            </div>
            <InputWithBytes v-model="des.key" placeholder="48位Hex (24字节)或16位Hex (8字节)" />
            <div v-if="desKeyHint" :class="['mt-1 text-xs', hintClass(desKeyHint)]"></div>
          </div>
          <div v-if="des.mode !== 'ECB'">
            <div class="flex justify-between mb-1">
              <label class="input-label !mb-0">IV (hex)</label>
              <Button variant="tool" size="sm" @click="genDesIV">⚡ 生成</Button>
            </div>
            <InputWithBytes v-model="des.iv" placeholder="16位Hex (8字节)" />
            <div v-if="desIVHint" :class="['mt-1 text-xs', hintClass(desIVHint)]"></div>
          </div>
        </Card>
      </div>

      <div class="space-y-3 sym-main">
        <Card>
          <label class="input-label">明文 (hex)</label>
          <div class="relative">
            <textarea v-model="des.plaintext" class="input min-h-[100px] resize-y pb-7" placeholder="输入hex格式数据..." />
            <ByteBadge :model-value="des.plaintext" />
          </div>
          <div v-if="desLenHint" :class="['mt-1 text-xs', hintClass(desLenHint)]"></div>
        </Card>
        <div class="flex gap-2 shrink-0">
          <Button variant="success" class="flex-1" @click="desEncrypt" :disabled="desDisabled"><LockIcon class="w-3.5 h-3.5" /> 加密</Button>
          <Button variant="warning" class="flex-1" @click="desDecrypt" :disabled="desDisabled"><UnlockIcon class="w-3.5 h-3.5" /> 解密</Button>
        </div>
        <ResultArea
          v-model="desResult.data"
          label="结果 (hex)"
          :success="desResult.success"
          :error="desResult.error"
          copyable
        />
        <ResultExtra v-model="desResult.extra" :label="`${des.iv ? '运算后' : '自动生成的'} IV`" />
      </div>
    </div>

    <!-- ChaCha20 Tab -->
    <div v-if="activeTab === 'chacha'" class="sym-workbench animate-fade-in">
      <!-- Left: params -->
      <div class="space-y-3 sym-side">
        <Card title="算法参数">
          <div>
            <label class="input-label">算法类型</label>
            <Dropdown
              v-model="chacha.type"
              :options="[
                { value: 'ChaCha20', label: 'ChaCha20' },
                { value: 'XChaCha20', label: 'XChaCha20' },
                { value: 'ChaCha20-Poly1305', label: 'ChaCha20-Poly1305 (AEAD)' },
                { value: 'XChaCha20-Poly1305', label: 'XChaCha20-Poly1305 (AEAD)' }
              ]"
            />
          </div>
        </Card>
        <Card title="密钥 & 参数">
          <div>
            <div class="flex justify-between mb-1">
              <label class="input-label !mb-0">密钥 (hex, 32字节)</label>
              <Button variant="tool" size="sm" @click="genChaChaKey">⚡ 生成</Button>
            </div>
            <InputWithBytes v-model="chacha.key" placeholder="64位hex (32字节)..." />
            <div v-if="chachaKeyHint" :class="['mt-1 text-xs', hintClass(chachaKeyHint)]">{{ chachaKeyHint }}</div>
          </div>
          <div>
            <div class="flex justify-between mb-1">
              <label class="input-label !mb-0">Nonce (hex)</label>
              <Button variant="tool" size="sm" @click="genChachaNonce">⚡ 生成</Button>
            </div>
            <InputWithBytes v-model="chacha.nonce" :placeholder="chacha.type.startsWith('X') ? '48位Hex (24字节)' : '24位Hex (12字节)'" />
            <div v-if="chachaNonceHint" :class="['mt-1 text-xs', hintClass(chachaNonceHint)]">{{ chachaNonceHint }}</div>
          </div>
          <div v-if="chacha.type.includes('Poly1305')">
            <label class="input-label">AAD (可选, hex)</label>
            <InputWithBytes v-model="chacha.aad" placeholder="附加认证数据..." />
            <div v-if="chachaAADHint" :class="['mt-1 text-xs', hintClass(chachaAADHint)]">{{ chachaAADHint }}</div>
          </div>
        </Card>
      </div>

      <!-- Middle: data + result -->
      <div class="sym-main">
        <Card class="flex-1 min-h-0 flex flex-col">
          <CryptoPanel v-model="chacha.data" label="数据 (Hex)" clearable type="textarea" :rows="3" />
          <div v-if="chachaLenHint" :class="['mt-1 text-xs', hintClass(chachaLenHint)]">{{ chachaLenHint }}</div>
          <div class="flex gap-2 shrink-0 mt-3">
            <Button variant="success" class="flex-1" @click="chachaEncrypt" :disabled="chachaDisabled"><LockIcon class="w-3.5 h-3.5" /> 加密</Button>
            <Button variant="warning" class="flex-1" @click="chachaDecrypt" :disabled="chachaDisabled"><UnlockIcon class="w-3.5 h-3.5" /> 解密</Button>
          </div>
        </Card>
        <ResultArea
          v-model="chachaResult.data"
          label="运算结果 (Hex)"
          :success="chachaResult.success"
          :error="chachaResult.error"
          copyable
        />
        <ResultExtra v-model="chachaResult.extra" label="自动生成 Nonce" />
      </div>
    </div>

    <!-- RC4 Tab -->
    <div v-if="activeTab === 'rc4'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="RC4 参数">
          <div>
            <div class="flex items-center justify-between mb-1">
              <label class="input-label !mb-0">密钥 (hex)</label>
              <Button variant="tool" size="sm" @click="genRC4Key">⚡ 生成</Button>
            </div>
            <InputWithBytes v-model="rc4.key" placeholder="1-256字节 Hex" />
            <div v-if="rc4KeyHint" :class="['mt-1 text-xs', hintClass(rc4KeyHint)]">{{ rc4KeyHint }}</div>
          </div>
        </Card>
        <Card>
          <CryptoPanel v-model="rc4.data" label="数据 (hex)" type="textarea" :rows="3" clearable />
          <div v-if="rc4LenHint" :class="['mt-1 text-xs', hintClass(rc4LenHint)]">{{ rc4LenHint }}</div>
        </Card>
        <div class="flex gap-2">
          <Button variant="success" class="flex-1" @click="rc4Encrypt" :disabled="rc4Disabled">
            <LockIcon class="w-3.5 h-3.5" /> RC4 加密
          </Button>
          <Button variant="warning" class="flex-1" @click="rc4Decrypt" :disabled="rc4Disabled">
            <UnlockIcon class="w-3.5 h-3.5" /> RC4 解密
          </Button>
        </div>
      </div>

      <div class="sym-main">
        <ResultArea
          v-model="rc4Result.data"
          label="运算结果 (Hex)"
          :success="rc4Result.success"
          :error="rc4Result.error"
          copyable
        />
      </div>
    </div>

    <!-- SIV Tab -->
    <div v-if="activeTab === 'siv'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="AES-SIV 参数">
          <div>
            <label class="input-label">模式</label>
            <Dropdown
              v-model="siv.mode"
              :options="[
                { value: 'AES-SIV', label: 'AES-SIV (RFC 5297)' },
                { value: 'AES-GCM-SIV', label: 'AES-GCM-SIV' }
              ]"
            />
          </div>
          <div>
            <div class="flex items-center justify-between mb-1">
              <label class="input-label !mb-0">密钥 (hex)</label>
              <Button variant="tool" size="sm" @click="genSIVKey">⚡ 生成</Button>
            </div>
            <InputWithBytes v-model="siv.key"
                   :placeholder="siv.mode === 'AES-SIV' ? '64/96/128位Hex (32/48/64字节)' : '32/64位Hex (16/32字节)'" />
            <div v-if="sivKeyHint" :class="['mt-1 text-xs', hintClass(sivKeyHint)]">{{ sivKeyHint }}</div>
          </div>
          <div>
            <label class="input-label">Nonce (hex)</label>
            <InputWithBytes v-model="siv.nonce"
                   :placeholder="siv.mode === 'AES-SIV' ? '可选 32位Hex (16字节) 或留空' : '必须 24位Hex (12字节)'" />
            <div v-if="sivNonceHint" :class="['mt-1 text-xs', hintClass(sivNonceHint)]">{{ sivNonceHint }}</div>
          </div>
          <div>
            <label class="input-label">AAD (可选, hex)</label>
            <InputWithBytes v-model="siv.aad" placeholder="附加认证数据..." />
            <div v-if="sivAADHint" :class="['mt-1 text-xs', hintClass(sivAADHint)]">{{ sivAADHint }}</div>
          </div>
        </Card>
        <Card>
          <CryptoPanel v-model="siv.data" label="数据 (hex)" type="textarea" :rows="3" clearable />
          <div v-if="sivLenHint" :class="['mt-1 text-xs', hintClass(sivLenHint)]">{{ sivLenHint }}</div>
        </Card>
        <div class="flex gap-2">
          <Button variant="success" class="flex-1" @click="sivEncrypt" :disabled="sivDisabled">
            <LockIcon class="w-3.5 h-3.5" /> 加密
          </Button>
          <Button variant="warning" class="flex-1" @click="sivDecrypt" :disabled="sivDisabled">
            <UnlockIcon class="w-3.5 h-3.5" /> 解密
          </Button>
        </div>
      </div>

      <div class="sym-main">
        <ResultArea
          v-model="sivResult.data"
          label="运算结果 (Hex)"
          :success="sivResult.success"
          :error="sivResult.error"
          copyable
        />
      </div>
    </div>

    <!-- FPE Tab -->
    <div v-if="activeTab === 'fpe'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="FPE 参数">
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="input-label">算法</label>
              <Dropdown
                v-model="fpe.cipher"
                :options="[
                  { value: 'AES', label: 'AES' },
                  { value: 'SM4', label: 'SM4' }
                ]"
              />
            </div>
            <div>
              <label class="input-label">模式</label>
              <Dropdown
                v-model="fpe.mode"
                :options="[
                  { value: 'FF1', label: 'FF1' },
                  { value: 'FF3-1', label: 'FF3-1' }
                ]"
              />
            </div>
            <div>
              <label class="input-label">字符集</label>
              <Dropdown
                v-model="fpe.alphabetMode"
                :options="[
                  { value: 'digits', label: '数字 (0-9)' },
                  { value: 'hex', label: 'Hex (0-9A-F)' },
                  { value: 'alnum', label: '数字+大写字母' },
                  { value: 'custom', label: '自定义' }
                ]"
              />
            </div>
          </div>
          <div v-if="fpe.alphabetMode === 'custom'">
            <label class="input-label">自定义字符集</label>
            <Input v-model="fpe.alphabetCustom" class="font-mono" placeholder="例如: ABCDEF0123" />
          </div>
          <div>
            <div class="flex items-center justify-between mb-1">
              <label class="input-label !mb-0">密钥 (hex)</label>
              <Button variant="tool" size="sm" @click="genFPEKey">⚡ 生成</Button>
            </div>
            <InputWithBytes v-model="fpe.key" :placeholder="fpe.cipher === 'SM4' ? '32位Hex (16字节)' : '32/48/64位Hex (16/24/32字节)'" />
            <div v-if="fpeKeyHint" :class="['mt-1 text-xs', hintClass(fpeKeyHint)]">{{ fpeKeyHint }}</div>
          </div>
          <div>
            <label class="input-label">Tweak (hex, 可选)</label>
            <InputWithBytes v-model="fpe.tweak"
                   :placeholder="fpe.mode === 'FF3-1' ? 'FF3-1需要14位Hex(7字节)，留空默认全0' : '留空则不使用'" />
            <div v-if="fpeTweakHint" :class="['mt-1 text-xs', hintClass(fpeTweakHint)]">{{ fpeTweakHint }}</div>
          </div>
        </Card>
        <Card>
          <CryptoPanel v-model="fpe.data" label="待处理数据" type="textarea" :rows="3" clearable />
          <div v-if="fpeLenHint" :class="['mt-1 text-xs', hintClass(fpeLenHint)]">{{ fpeLenHint }}</div>
        </Card>
        <div class="flex gap-2">
          <Button variant="success" class="flex-1" @click="fpeEncrypt" :disabled="fpeDisabled">
            <LockIcon class="w-3.5 h-3.5" /> FPE 加密
          </Button>
          <Button variant="warning" class="flex-1" @click="fpeDecrypt" :disabled="fpeDisabled">
            <UnlockIcon class="w-3.5 h-3.5" /> FPE 解密
          </Button>
        </div>
      </div>

      <div class="sym-main">
        <ResultArea
          v-model="fpeResult.data"
          label="运算结果"
          :success="fpeResult.success"
          :error="fpeResult.error"
          copyable
        />
        <p class="text-[10px] opacity-70 italic font-mono">输入限制: 长度 >= {{ fpeMinLen }}；最大 {{ fpeMaxLen }}</p>
      </div>
    </div>

  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useRoute } from 'vue-router'
import { LockIcon, UnlockIcon, AlertCircleIcon, ZapIcon, PackageIcon, PackageOpenIcon, ShieldCheckIcon } from '@lucide/vue'
import PageLayout from '../components/PageLayout.vue'
import Card from '../components/Card.vue'
import Input from '../components/Input.vue'
import InputWithBytes from '../components/InputWithBytes.vue'
import Button from '../components/Button.vue'
import ResultArea from '../components/ResultArea.vue'
import ResultExtra from '../components/ResultExtra.vue'
import AlgorithmDrawer from '../components/AlgorithmDrawer.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import Dropdown from '../components/Dropdown.vue'
import ByteBadge from '../components/ByteBadge.vue'
import {
  AESEncrypt, AESDecrypt, DESEncrypt, DESDecrypt, ChaCha20Encrypt, ChaCha20Decrypt,
  RC4Encrypt, RC4Decrypt, SIVEncrypt, SIVDecrypt, FPEEncrypt, FPEDecrypt,
  SM4Encrypt, SM4Decrypt, ZUCEncrypt, MakeGMEnvelope, OpenGMEnvelope
} from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'
import { formatHexBytes } from '../utils/format'

const store = useAppStore()
const route = useRoute()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'aes', label: 'AES' },
  { id: 'sm4', label: 'SM4' },
  { id: 'zuc', label: 'ZUC' },
  { id: 'envelope', label: '数字信封' },
  { id: 'des', label: 'DES / 3DES' },
  { id: 'chacha', label: 'ChaCha20' },
  { id: 'siv', label: 'AES-SIV' },
  { id: 'rc4', label: 'RC4' },
  { id: 'fpe', label: 'FPE' },
]
const activeTab = ref('aes')

const keySizeOptions = [
  { value: '128', label: 'AES-128' },
  { value: '192', label: 'AES-192' },
  { value: '256', label: 'AES-256' }
]

// ── 算法原理 ────────────────────────────────────────────────
const drawerOpen = ref(false)
const principles = {
  'aes-mode': {
    title: 'AES 加密模式选择指南',
    content: 'ECB (电子密码本): 最简单，每个块独立加密。缺点：相同明文块产生相同密文块，安全性低，仅限测试使用。\nCBC (密码分组链接): 最常用模式之一。每个明文块与前一个密文块异或后再加密。优点：安全性高，隐藏明文模式；缺点：无法并行，需 IV。\nCFB/OFB (反馈模式): 将分组密码转换为流密码。适合实时流数据，不需填充。\nCTR (计数器模式): 将计数器加密后与明文异或。优点：高性能、可并行、支持随机访问，是现代协议常用模式。\nGCM (伽罗瓦/计数器模式): 现代首选。提供加密的同时提供完整性校验 (AEAD)，安全性与性能平衡最佳。'
  },
  'aes-padding': {
    title: '对称加密填充方式说明',
    content: 'PKCS7: 最通用标准。填充字节的值等于填充的字节数。例如缺 3 字节则填充 03 03 03。\nZero Padding: 填充 0x00。注意：若明文末尾本身有 0x00，解密后可能无法区分填充。\nISO10126: 填充随机字节，最后一个字节记录填充长度。安全性略高于 PKCS7。\nNoPadding: 不填充。要求输入明文长度必须是分组长度 (AES 为 16 字节) 的整数倍。'
  },
  aes: {
    title: 'AES (高级加密标准) 原理',
    content: '设计背景: 旨在取代 DES，采用 Rijndael 算法，是目前全球应用最广的对称加密标准。\n核心流程: 经过字节替代 (SubBytes)、行移位 (ShiftRows)、列混淆 (MixColumns) 和轮密钥加 (AddRoundKey) 的多轮迭代。\n安全强度:\n• AES-128: 10 轮迭代\n• AES-192: 12 轮迭代\n• AES-256: 14 轮迭代\n模式建议:\n• GCM: 现代首选，带认证的加密 (AEAD)，性能高且防篡改。\n• CBC: 传统常用，需配合 MAC 才能防篡改。'
  },
  sm4: {
    title: 'SM4 (国密分组加密) 原理',
    content: '设计背景: 我国自主设计的第一个商用分组密码标准 (GM/T 0002)。\n技术特征:\n• 分组长度: 128 位\n• 密钥长度: 128 位\n• 迭代轮数: 32 轮\n• 算法结构: 非平衡 Feistel 网络结构，但实际上是一种全分组置换。\n应用场景: 广泛用于金融、政务、物联网等需要符合国家密码标准合规的场景。'
  },
  zuc: {
    title: 'ZUC (祖冲之算法) 原理',
    content: '设计背景: 面向 3GPP LTE 移动通信系统的序列密码 (流密码) 标准。\n技术特征:\n• 结构: 由线性反馈移位寄存器 (LFSR)、比特重组 (BR) 和非线性函数 F 组成。\n• 版本: ZUC-128 (4G) 和 ZUC-256 (5G 增强安全)。\n应用场景: 移动网络数据加密和完整性保护。流密码具有极高的软件处理性能，且不会产生长度扩展。'
  },
  envelope: {
    title: '数字信封 (SM2 + SM4) 原理',
    content: '设计目标: 解决大规模数据传输时的密钥分发问题。\n核心步骤:\n1. 密封 (封包): 发送方生成随机对称密钥 (SM4)，用它加密大数据；然后用接收方的公钥 (SM2) 加密该 SM4 密钥。\n2. 拆解 (解包): 接收方先用自己的私钥解密出 SM4 密钥，再用该密钥解密大数据。\n优势: 兼具非对称加密的安全分发和对称加密的高效处理性能。'
  },
  des: {
    title: 'DES / 3DES 原理',
    content: 'DES: 1977 年标准，56 位密钥长度，目前已能被暴力破解，仅用于遗留系统兼容。\n3DES: 为增强安全，对数据进行三次 DES 运算。通常采用 K1-K2-K3 或 K1-K2-K1 三密钥模式。\n安全性: 3DES 的安全强度约为 112 位，虽然目前尚算安全，但计算效率远低于 AES，建议迁移至 AES 或 SM4。'
  },
  chacha: {
    title: 'ChaCha20 原理',
    content: '设计背景: 由 Daniel J. Bernstein 设计的流密码，旨在提供比 AES 更高的纯软件性能。\n技术特征:\n• 结构: 基于 ARX (Addition-Rotation-XOR) 设计，不依赖查表，天然防御侧信道攻击。\n• Poly1305: 常配合 Poly1305 构成 AEAD 模式。\n应用场景: TLS 1.3、移动端、以及没有硬件 AES 指令集的低端处理器。'
  },
  siv: {
    title: 'AES-SIV (合成初始向量) 原理',
    content: '设计目标: 解决传统 AEAD 模式下，一旦 Nonce 重复就会导致密钥泄漏的致命缺陷。\n工作方式: 采用“确定性”加密，IV 是由明文本身和附加数据经过 PRF 计算得到的。即使 Nonce 错误地重复，也只会泄漏“明文是否相同”，而不会泄漏密钥或明文内容。'
  },
  rc4: {
    title: 'RC4 原理',
    content: '设计背景: 曾经世界上最流行的流密码，结构极其简单（S盒交换）。\n安全性缺陷: 存在初始字节偏置等弱点，目前在所有主流协议 (如 TLS 1.2+) 中已被禁用。\n仅供参考: 除非维护极其古老的系统，否则绝不建议在新项目中使用。'
  },
  fpe: {
    title: 'FPE (格式保持加密) 原理',
    content: '设计目标: 加密后的密文与明文保持相同的格式和长度。例如：16位银行卡号加密后仍是16位数字。\n标准: 基于 NIST SP 800-38G 标准的 FF1 和 FF3-1 模式。\n应用场景: 数据库敏感字段脱敏、遗留系统数据库改造（无需修改字段定义长度）。'
  }
}
const currentPrinciple = computed(() => {
  const base = principles[activeTab.value]
  if (!base) return { title: '', content: '' }
  
  // Make title dynamic based on current settings
  let title = base.title
  if (activeTab.value === 'aes') {
    title = `AES-${aes.keySize} ${aes.mode} 模式原理`
  } else if (activeTab.value === 'des') {
    title = `${des.type} ${des.mode} 模式原理`
  } else if (activeTab.value === 'sm4') {
    title = `SM4 ${sm4.mode} 模式原理`
  } else if (activeTab.value === 'chacha') {
    title = `${chacha.type} 原理`
  } else if (activeTab.value === 'siv') {
    title = `${siv.mode} 原理`
  } else if (activeTab.value === 'zuc') {
    title = `${zuc.type} 原理`
  } else if (activeTab.value === 'fpe') {
    title = `FPE ${fpe.mode} (${fpe.cipher}) 原理`
  }
  
  // Build dynamic content with mode/padding info
  let content = base.content
  if (activeTab.value === 'aes') {
    const modeInfo = {
      'ECB': '当前模式: ECB - 每个块独立加密，不推荐用于生产环境。',
      'CBC': '当前模式: CBC - 需要 IV，传统常用模式，需配合 MAC 防篡改。\n未提供 IV 时自动生成，Extra 返回实际使用的 IV。',
      'CFB': '当前模式: CFB - 流式处理，不需要填充。',
      'OFB': '当前模式: OFB - 独立密钥流，错误不扩散。',
      'CTR': '当前模式: CTR - 高性能可并行，需额外完整性校验。\n运算后计数器递增，Nonce 保持不变。',
      'GCM': '当前模式: GCM - 现代首选 AEAD 模式，一次完成加密和完整性校验。',
      'CCM': '当前模式: CCM - AEAD 模式，常见于嵌入式和 IoT 协议。'
    }
    const paddingInfo = {
      'PKCS7': '当前填充: PKCS7 - 最通用标准。',
      'Zero': '当前填充: Zero Padding - 填充 0x00。',
      'ISO10126': '当前填充: ISO10126 - 随机字节填充。',
      'NoPadding': '当前填充: NoPadding - 要求数据长度为 16 字节倍数。'
    }
    content += '\n\n' + (modeInfo[aes.mode] || '')
    if (!['GCM', 'CCM', 'CFB', 'OFB', 'CTR'].includes(aes.mode)) {
      content += '\n' + (paddingInfo[aes.padding] || '')
    }
  } else if (activeTab.value === 'des') {
    const modeInfo = {
      'ECB': '当前模式: ECB - 不需要 IV，但会暴露重复块形状。',
      'CBC': '当前模式: CBC - 遗留系统最常见选项。未提供 IV 时自动生成，Extra 返回实际使用的 IV。',
      'CFB': '当前模式: CFB - 可做流式处理。',
      'OFB': '当前模式: OFB - 独立密钥流。',
      'CTR': '当前模式: CTR - 可并行处理。'
    }
    content += '\n\n' + (modeInfo[des.mode] || '')
  } else if (activeTab.value === 'sm4') {
    const modeInfo = {
      'ECB': '当前模式: ECB - 每个块独立加密。',
      'CBC': '当前模式: CBC - 需要 IV，最常用模式。未提供 IV 时自动生成，Extra 返回实际使用的 IV。',
      'CFB': '当前模式: CFB - 流式处理。',
      'OFB': '当前模式: OFB - 独立密钥流。',
      'CTR': '当前模式: CTR - 高性能可并行。运算后计数器递增。',
      'GCM': '当前模式: GCM - AEAD 模式，带认证加密。'
    }
    content += '\n\n' + (modeInfo[sm4.mode] || '')
  }
  
  return { title, content }
})

const parsedPrinciples = computed(() => {
  if (!currentPrinciple.value) return []
  const lines = currentPrinciple.value.content.split('\n')
  const sections = []
  let currentSection = null

  lines.forEach(line => {
    if (line.includes(':') && !line.startsWith('•')) {
      const [title, ...rest] = line.split(':')
      currentSection = { title: title.trim(), content: [rest.join(':').trim()] }
      sections.push(currentSection)
    } else if (currentSection) {
      if (line.trim()) currentSection.content.push(line.trim())
    }
  })

  // Fallback if no colon titles found
  if (sections.length === 0) {
    return [{ title: '详细说明', content: lines.filter(l => l.trim()) }]
  }
  return sections
})

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

// AES state
const aes = reactive({
  keySize: '256', mode: 'CBC', padding: 'PKCS7', inputFormat: 'hex',
  key: '', iv: '', nonce: '', aad: '', plaintext: '',
})
const result = reactive({ data: '', error: '', extra: '', success: null })

function toHex(str) {
  if (aes.inputFormat === 'hex') return str.trim()
  return Array.from(new TextEncoder().encode(str)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase()
}

async function encrypt() {
  result.data = ''; result.error = ''; result.extra = ''
  const cleanData = aes.plaintext.replace(/\s+/g, '')
  if (aes.padding === 'NoPadding' && cleanData.length % 32 !== 0) {
    result.success = false
    result.error = '错误：在 NoPadding 模式下，输入数据的长度必须是 16 字节（32 位 Hex）的倍数'
    return
  }
  try {
    const req = {
      key: aes.key, iv: aes.iv, nonce: aes.nonce, aad: aes.aad,
      data: toHex(aes.plaintext), mode: aes.mode, padding: aes.padding,
      keySize: parseInt(aes.keySize), tagSize: 16,
    }
    const r = await AESEncrypt(req)
    result.data = r.data; result.error = r.error; result.extra = r.extra
    result.success = r.success
    if (r.success) store.addToHistory(`AES-${aes.keySize}-${aes.mode}`, r.data)
  } catch (e) { result.error = String(e); result.success = false }
}

async function decrypt() {
  result.data = ''; result.error = ''; result.extra = ''
  try {
    const req = {
      key: aes.key, iv: aes.iv, nonce: aes.nonce, aad: aes.aad,
      data: toHex(aes.plaintext), mode: aes.mode, padding: aes.padding,
      keySize: parseInt(aes.keySize), tagSize: 16,
    }
    const r = await AESDecrypt(req)
    if (r.success && aes.inputFormat === 'text') {
      result.data = new TextDecoder().decode(new Uint8Array(r.data.match(/.{2}/g).map(b => parseInt(b, 16))))
    } else {
      result.data = r.data
    }
    result.error = r.error; result.success = r.success
    // 解密成功后显示使用的IV/Nonce
    if (r.success && !['ECB'].includes(aes.mode)) {
      if (['GCM', 'CCM'].includes(aes.mode)) {
        result.extra = aes.nonce
      } else {
        result.extra = aes.iv
      }
    }
  } catch (e) { result.error = String(e); result.success = false }
}

function genKey() {
  const len = parseInt(aes.keySize) / 8
  const b = new Uint8Array(len); crypto.getRandomValues(b)
  aes.key = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}
function genIV() {
  const b = new Uint8Array(16); crypto.getRandomValues(b)
  aes.iv = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}
function genNonce() {
  const b = new Uint8Array(12); crypto.getRandomValues(b)
  aes.nonce = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

// DES state
const des = reactive({ type: 'DES', mode: 'CBC', padding: 'PKCS7', key: '', iv: '', plaintext: '' })
const desResult = reactive({ data: '', error: '', extra: '', success: null })

async function desEncrypt() {
  const cleanData = des.plaintext.replace(/\s+/g, '')
  if (des.padding === 'NoPadding' && cleanData.length % 16 !== 0) {
    desResult.success = false
    desResult.error = '错误：在 NoPadding 模式下，DES 输入数据的长度必须是 8 字节（16 位 Hex）的倍数'
    return
  }
  try {
    const r = await DESEncrypt({ ...des, data: des.plaintext })
    desResult.data = r.data; desResult.error = r.error; desResult.success = r.success
  } catch (e) { desResult.error = String(e) }
}
async function desDecrypt() {
  try {
    const r = await DESDecrypt({ ...des, data: des.plaintext })
    desResult.data = r.data; desResult.error = r.error; desResult.success = r.success
    // Show IV used for decryption
    if (r.success && des.mode !== 'ECB') {
      desResult.extra = des.iv
    }
  } catch (e) { desResult.error = String(e) }
}
function genDesKey() {
  const len = des.type === '3DES' ? 24 : 8
  const b = new Uint8Array(len); crypto.getRandomValues(b)
  des.key = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}
function genDesIV() {
  const b = new Uint8Array(8); crypto.getRandomValues(b)
  des.iv = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

// ChaCha20 state
const chacha = reactive({ type: 'ChaCha20-Poly1305', key: '', nonce: '', aad: '', data: '' })
const chachaResult = reactive({ data: '', error: '', extra: '', success: null })

async function chachaEncrypt() {
  try {
    const r = await ChaCha20Encrypt(chacha)
    chachaResult.data = r.data; chachaResult.error = r.error
    chachaResult.extra = r.extra; chachaResult.success = r.success
  } catch (e) { chachaResult.error = String(e) }
}
async function chachaDecrypt() {
  try {
    const r = await ChaCha20Decrypt(chacha)
    chachaResult.data = r.data; chachaResult.error = r.error; chachaResult.success = r.success
  } catch (e) { chachaResult.error = String(e) }
}
function genChaChaKey() {
  const b = new Uint8Array(32); crypto.getRandomValues(b)
  chacha.key = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}
function genChachaNonce() {
  const size = chacha.type.startsWith('X') ? 24 : 12
  const b = new Uint8Array(size); crypto.getRandomValues(b)
  chacha.nonce = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

// SIV state
const siv = reactive({ mode: 'AES-SIV', key: '', nonce: '', aad: '', data: '' })
const sivResult = reactive({ data: '', error: '', success: null })

function genSIVKey() {
  const len = siv.mode === 'AES-SIV' ? 32 : 16
  const b = new Uint8Array(len); crypto.getRandomValues(b)
  siv.key = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

async function sivEncrypt() {
  sivResult.data = ''; sivResult.error = ''
  siv.key = siv.key.toUpperCase(); siv.nonce = siv.nonce.toUpperCase(); siv.aad = siv.aad.toUpperCase(); siv.data = siv.data.toUpperCase()
  const r = await SIVEncrypt(siv)
  sivResult.data = r.data; sivResult.error = r.error; sivResult.success = r.success
}

async function sivDecrypt() {
  sivResult.data = ''; sivResult.error = ''
  siv.key = siv.key.toUpperCase(); siv.nonce = siv.nonce.toUpperCase(); siv.aad = siv.aad.toUpperCase(); siv.data = siv.data.toUpperCase()
  const r = await SIVDecrypt(siv)
  sivResult.data = r.data; sivResult.error = r.error; sivResult.success = r.success
}

// RC4 state
const rc4 = reactive({ key: '', data: '' })
const rc4Result = reactive({ data: '', error: '', success: null })

function genRC4Key() {
  const b = new Uint8Array(16); crypto.getRandomValues(b)
  rc4.key = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

async function rc4Encrypt() {
  rc4Result.data = ''; rc4Result.error = ''
  rc4.key = rc4.key.toUpperCase()
  rc4.data = rc4.data.toUpperCase()
  const r = await RC4Encrypt({ key: rc4.key, data: rc4.data })
  rc4Result.data = r.data; rc4Result.error = r.error; rc4Result.success = r.success
}

async function rc4Decrypt() {
  rc4Result.data = ''; rc4Result.error = ''
  rc4.key = rc4.key.toUpperCase()
  rc4.data = rc4.data.toUpperCase()
  const r = await RC4Decrypt({ key: rc4.key, data: rc4.data })
  rc4Result.data = r.data; rc4Result.error = r.error; rc4Result.success = r.success
}

// SM4 state
const sm4 = reactive({ mode: 'CBC', padding: 'PKCS7', key: '', iv: '', nonce: '', aad: '', data: '' })
const sm4Result = reactive({ data: '', error: '', extra: '', success: null })

async function doSM4Encrypt() {
  const cleanData = sm4.data.replace(/\s+/g, '')
  if (sm4.padding === 'NoPadding' && cleanData.length % 32 !== 0) {
    sm4Result.success = false
    sm4Result.error = '错误：在 NoPadding 模式下，输入数据的长度必须是 16 字节（32 位 Hex）的倍数'
    return
  }
  const r = await SM4Encrypt(sm4)
  sm4Result.data = r.data; sm4Result.error = r.error; sm4Result.extra = r.extra; sm4Result.success = r.success
}
async function doSM4Decrypt() {
  const cleanData = sm4.data.replace(/\s+/g, '')
  if (cleanData.length % 32 !== 0) {
    sm4Result.success = false
    sm4Result.error = '错误：SM4 密文长度必须是 16 字节（32 位 Hex）的倍数'
    return
  }
  const r = await SM4Decrypt(sm4)
  sm4Result.data = r.data; sm4Result.error = r.error; sm4Result.success = r.success
  // Show IV used for decryption
  if (r.success && sm4.mode !== 'ECB') {
    if (sm4.mode === 'GCM') {
      sm4Result.extra = sm4.nonce
    } else {
      sm4Result.extra = sm4.iv
    }
  }
}
function genSM4Key() { const b = new Uint8Array(16); crypto.getRandomValues(b); sm4.key = Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase() }
function genSM4IV()  { const b = new Uint8Array(16); crypto.getRandomValues(b); sm4.iv  = Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase() }
function genSM4Nonce(){ const b = new Uint8Array(12); crypto.getRandomValues(b); sm4.nonce= Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase() }

// ZUC state
const zuc = reactive({ type: 'ZUC-128', key: '', iv: '', data: '' })
const zucResult = reactive({ data: '', error: '', success: null })

async function doZUCEncrypt() {
  const r = await ZUCEncrypt(zuc)
  zucResult.data = r.data; zucResult.error = r.error; zucResult.success = r.success
}
function genZUCKey() {
  const len = zuc.type === 'ZUC-256' ? 32 : 16
  const b = new Uint8Array(len); crypto.getRandomValues(b)
  zuc.key = Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase()
}
function genZUCIV() {
  const len = zuc.type === 'ZUC-256' ? 25 : 16
  const b = new Uint8Array(len); crypto.getRandomValues(b)
  zuc.iv = Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase()
}

// Envelope state
const envelope = reactive({ senderPriv: '', receiverPub: '', data: '', receiverPriv: '', senderPub: '', envelopeData: '' })
const envelopeResult = reactive({ data: '', error: '', success: null })

async function makeEnvelope() {
  if (!envelope.senderPriv || !envelope.receiverPub || !envelope.data) {
    envelopeResult.error = '请填写完整的发送方私钥、接收方公钥和待处理数据'
    envelopeResult.success = false
    return
  }
  const r = await MakeGMEnvelope(envelope)
  envelopeResult.data = r.data; envelopeResult.error = r.error; envelopeResult.success = r.success
}
async function openEnvelope() {
  if (!envelope.receiverPriv || !envelope.senderPub || !envelope.envelopeData) {
    envelopeResult.error = '请填写完整的接收方私钥、发送方公钥和信封数据'
    envelopeResult.success = false
    return
  }
  const r = await OpenGMEnvelope(envelope)
  envelopeResult.data = r.data; envelopeResult.error = r.error; envelopeResult.success = r.success
}

// FPE state
const fpe = reactive({
  mode: 'FF1',
  cipher: 'AES',
  alphabetMode: 'digits',
  alphabetCustom: '',
  key: '',
  tweak: '',
  data: '',
})
const fpeResult = reactive({ data: '', error: '', success: null })

const fpeAlphabet = computed(() => {
  switch (fpe.alphabetMode) {
    case 'hex':
      return '0123456789ABCDEF'
    case 'alnum':
      return '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    case 'custom':
      return fpe.alphabetCustom || ''
    default:
      return '0123456789'
  }
})
const fpeRadix = computed(() => fpeAlphabet.value.length || 10)
const fpeMinLen = computed(() => Math.ceil(6 / Math.log10(fpeRadix.value)))
const fpeMaxLen = computed(() => {
  if (fpe.mode === 'FF3-1') return Math.floor(192 / Math.log2(fpeRadix.value))
  return '2^32'
})

const cleanHex = (s) => (s || '').replace(/\s+/g, '')
const hexByteLen = (s) => cleanHex(s).length / 2
const hasOddHex = (s) => cleanHex(s).length % 2 !== 0

const aesLenHint = computed(() => {
  if (aes.inputFormat !== 'hex') return ''
  const clean = cleanHex(aes.plaintext)
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'Hex 长度必须为偶数位'
  if (aes.padding === 'NoPadding' && clean.length % 32 !== 0) {
    return 'NoPadding 时长度必须是 16 字节(32位Hex)的倍数'
  }
  return ''
})
const aesKeyHint = computed(() => {
  const clean = cleanHex(aes.key)
  if (!clean) return ''
  if (hasOddHex(aes.key)) return '密钥 Hex 长度必须为偶数位'
  const bytes = hexByteLen(aes.key)
  const need = parseInt(aes.keySize) / 8
  if (bytes !== need) return `AES-${aes.keySize} 需要 ${need} 字节(${need * 2}位Hex)密钥`
  return ''
})
const aesIVHint = computed(() => {
  if (['ECB', 'GCM', 'CCM'].includes(aes.mode)) return ''
  const clean = cleanHex(aes.iv)
  if (!clean) return ''
  if (hasOddHex(aes.iv)) return 'IV Hex 长度必须为偶数位'
  if (clean.length !== 32) return 'IV 必须为 16 字节(32位Hex)'
  return ''
})
const aesNonceHint = computed(() => {
  if (!['GCM', 'CCM'].includes(aes.mode)) return ''
  const clean = cleanHex(aes.nonce)
  if (!clean) return ''
  if (hasOddHex(aes.nonce)) return 'Nonce Hex 长度必须为偶数位'
  if (clean.length !== 24) return 'Nonce 建议 12 字节(24位Hex)'
  return ''
})
const aesAADHint = computed(() => {
  const clean = cleanHex(aes.aad)
  if (!clean) return ''
  if (hasOddHex(aes.aad)) return 'AAD Hex 长度必须为偶数位'
  return ''
})

const desLenHint = computed(() => {
  const clean = cleanHex(des.plaintext)
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'Hex 长度必须为偶数位'
  if (des.padding === 'NoPadding' && clean.length % 16 !== 0) {
    return 'NoPadding 时长度必须是 8 字节(16位Hex)的倍数'
  }
  return ''
})
const desKeyHint = computed(() => {
  const clean = cleanHex(des.key)
  if (!clean) return ''
  if (hasOddHex(des.key)) return '密钥 Hex 长度必须为偶数位'
  const bytes = hexByteLen(des.key)
  if (des.type === '3DES') {
    if (bytes !== 24) return '3DES 密钥必须为 24 字节(48位Hex)'
  } else if (bytes !== 8) {
    return 'DES 密钥必须为 8 字节(16位Hex)'
  }
  return ''
})
const desIVHint = computed(() => {
  if (des.mode === 'ECB') return ''
  const clean = cleanHex(des.iv)
  if (!clean) return ''
  if (hasOddHex(des.iv)) return 'IV Hex 长度必须为偶数位'
  if (clean.length !== 16) return 'IV 必须为 8 字节(16位Hex)'
  return ''
})

const chachaLenHint = computed(() => {
  const clean = cleanHex(chacha.data)
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'Hex 长度必须为偶数位'
  return ''
})
const chachaKeyHint = computed(() => {
  const clean = cleanHex(chacha.key)
  if (!clean) return ''
  if (hasOddHex(chacha.key)) return '密钥 Hex 长度必须为偶数位'
  if (clean.length !== 64) return '密钥必须为 32 字节(64位Hex)'
  return ''
})
const chachaNonceHint = computed(() => {
  const clean = cleanHex(chacha.nonce)
  if (!clean) return ''
  if (hasOddHex(chacha.nonce)) return 'Nonce Hex 长度必须为偶数位'
  const need = chacha.type.startsWith('X') ? 48 : 24
  if (clean.length !== need) return `Nonce 必须为 ${need / 2} 字节(${need}位Hex)`
  return ''
})
const chachaAADHint = computed(() => {
  const clean = cleanHex(chacha.aad)
  if (!clean) return ''
  if (hasOddHex(chacha.aad)) return 'AAD Hex 长度必须为偶数位'
  return ''
})

const sivLenHint = computed(() => {
  const clean = cleanHex(siv.data)
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'Hex 长度必须为偶数位'
  return ''
})
const sivKeyHint = computed(() => {
  const clean = cleanHex(siv.key)
  if (!clean) return ''
  if (hasOddHex(siv.key)) return '密钥 Hex 长度必须为偶数位'
  const bytes = hexByteLen(siv.key)
  if (siv.mode === 'AES-SIV') {
    if (![32, 48, 64].includes(bytes)) return 'AES-SIV 密钥必须为 32/48/64 字节'
  } else if (![16, 32].includes(bytes)) {
    return 'AES-GCM-SIV 密钥必须为 16/32 字节'
  }
  return ''
})
const sivNonceHint = computed(() => {
  const clean = cleanHex(siv.nonce)
  if (!clean) return ''
  if (hasOddHex(siv.nonce)) return 'Nonce Hex 长度必须为偶数位'
  if (siv.mode === 'AES-SIV') {
    if (clean.length !== 32) return 'AES-SIV Nonce 需为 16 字节(32位Hex)或留空'
  } else if (clean.length !== 24) {
    return 'AES-GCM-SIV Nonce 必须为 12 字节(24位Hex)'
  }
  return ''
})
const sivAADHint = computed(() => {
  const clean = cleanHex(siv.aad)
  if (!clean) return ''
  if (hasOddHex(siv.aad)) return 'AAD Hex 长度必须为偶数位'
  return ''
})

const rc4LenHint = computed(() => {
  const clean = cleanHex(rc4.data)
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'Hex 长度必须为偶数位'
  return ''
})
const rc4KeyHint = computed(() => {
  const clean = cleanHex(rc4.key)
  if (!clean) return ''
  if (hasOddHex(rc4.key)) return '密钥 Hex 长度必须为偶数位'
  const bytes = hexByteLen(rc4.key)
  if (bytes < 1 || bytes > 256) return '密钥长度需在 1~256 字节'
  return ''
})

const fpeLenHint = computed(() => {
  if (!fpe.data) return ''
  const n = fpe.data.length
  if (fpe.mode === 'FF3-1' && typeof fpeMaxLen.value === 'number') {
    if (n < fpeMinLen.value || n > fpeMaxLen.value) {
      return `长度必须在 ${fpeMinLen.value}~${fpeMaxLen.value}`
    }
    return ''
  }
  if (n < fpeMinLen.value) return `长度至少为 ${fpeMinLen.value}`
  return ''
})

function hintClass(text) {
  if (!text) return ''
  if (text.includes('必须') || text.includes('需') || text.includes('应为')) return 'text-red-400'
  return 'text-orange-300'
}

const aesDisabled = computed(() => !aes.key || !!(aesKeyHint.value || aesIVHint.value || aesNonceHint.value || aesAADHint.value || aesLenHint.value))
const desDisabled = computed(() => !des.key || !!(desKeyHint.value || desIVHint.value || desLenHint.value))
const chachaDisabled = computed(() => !chacha.key || !chacha.nonce || !!(chachaKeyHint.value || chachaNonceHint.value || chachaAADHint.value || chachaLenHint.value))
const rc4Disabled = computed(() => !rc4.key || !!(rc4KeyHint.value || rc4LenHint.value))
const sivDisabled = computed(() => !siv.key || !!(sivKeyHint.value || sivNonceHint.value || sivAADHint.value || sivLenHint.value))
const fpeDisabled = computed(() => !fpe.key || !!(fpeKeyHint.value || fpeTweakHint.value || fpeLenHint.value))
const fpeKeyHint = computed(() => {
  const clean = cleanHex(fpe.key)
  if (!clean) return ''
  if (hasOddHex(fpe.key)) return '密钥 Hex 长度必须为偶数位'
  const bytes = hexByteLen(fpe.key)
  if (fpe.cipher === 'SM4') {
    if (bytes !== 16) return 'SM4 密钥必须为 16 字节(32位Hex)'
  } else if (![16, 24, 32].includes(bytes)) {
    return 'AES 密钥必须为 16/24/32 字节(32/48/64位Hex)'
  }
  return ''
})
const fpeTweakHint = computed(() => {
  const clean = cleanHex(fpe.tweak)
  if (!clean) return ''
  if (hasOddHex(fpe.tweak)) return 'Tweak Hex 长度必须为偶数位'
  if (fpe.mode === 'FF3-1' && clean.length !== 14) return 'FF3-1 Tweak 必须为 7 字节(14位Hex)'
  return ''
})

function genFPEKey() {
  const len = fpe.cipher === 'SM4' ? 16 : 16
  const b = new Uint8Array(len); crypto.getRandomValues(b)
  fpe.key = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

async function fpeEncrypt() {
  fpeResult.data = ''; fpeResult.error = ''
  fpe.key = fpe.key.toUpperCase()
  fpe.tweak = fpe.tweak.toUpperCase()
  if (fpe.alphabetMode === 'hex') fpe.data = fpe.data.toUpperCase()
  const data = fpe.data
  const r = await FPEEncrypt({
    key: fpe.key.toUpperCase(),
    tweak: fpe.tweak.toUpperCase(),
    data,
    alphabet: fpeAlphabet.value,
    cipher: fpe.cipher,
    mode: fpe.mode,
  })
  fpeResult.data = r.data; fpeResult.error = r.error; fpeResult.success = r.success
}

async function fpeDecrypt() {
  fpeResult.data = ''; fpeResult.error = ''
  fpe.key = fpe.key.toUpperCase()
  fpe.tweak = fpe.tweak.toUpperCase()
  if (fpe.alphabetMode === 'hex') fpe.data = fpe.data.toUpperCase()
  const data = fpe.data
  const r = await FPEDecrypt({
    key: fpe.key.toUpperCase(),
    tweak: fpe.tweak.toUpperCase(),
    data,
    alphabet: fpeAlphabet.value,
    cipher: fpe.cipher,
    mode: fpe.mode,
  })
  fpeResult.data = r.data; fpeResult.error = r.error; fpeResult.success = r.success
}
</script>

<style scoped>
.sym-workbench {
  display: grid;
  grid-template-columns: minmax(400px, 1.2fr) 1fr;
  gap: 12px;
  align-items: start;
}

@media (min-width: 1440px) {
  .sym-workbench {
    grid-template-columns: minmax(450px, 1.3fr) 1fr;
    gap: 16px;
  }
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
