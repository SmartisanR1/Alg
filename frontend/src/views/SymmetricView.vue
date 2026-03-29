<template>
  <PageLayout title="对称算法" subtitle="AES · DES/3DES · ChaCha20 · 全模式支持"
              icon-bg="bg-blue-500/20"
              :tabs="tabs" :active-tab="activeTab"
              @tab-change="activeTab = $event">
    <template #icon>
      <LockIcon class="w-4 h-4 text-blue-400" />
    </template>


    <!-- AES Tab -->
    <div v-if="activeTab === 'aes'" class="grid grid-cols-3 gap-4 animate-fade-in h-full overflow-hidden">
      <!-- Left: params -->
      <div class="space-y-3 flex flex-col min-h-0 overflow-y-auto">
        <div class="ck-card">
          <p class="ck-section-title">算法参数</p>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="ck-label">密钥长度</label>
              <select v-model="aes.keySize" class="ck-select">
                <option value="128">AES-128</option>
                <option value="192">AES-192</option>
                <option value="256" selected>AES-256</option>
              </select>
            </div>
            <div>
              <label class="ck-label">加密模式</label>
              <select v-model="aes.mode" class="ck-select">
                <option>ECB</option><option>CBC</option><option>CFB</option>
                <option>OFB</option><option>CTR</option><option>GCM</option>
                <option>CCM</option>
              </select>
            </div>
            <div>
              <label class="ck-label">填充方式</label>
              <select v-model="aes.padding" class="ck-select"
                      :disabled="['CTR','GCM','CCM','CFB','OFB'].includes(aes.mode)">
                <option>PKCS7</option><option>Zero</option>
                <option>ISO10126</option><option>NoPadding</option>
              </select>
            </div>
            <div>
              <label class="ck-label">输入格式</label>
              <select v-model="aes.inputFormat" class="ck-select">
                <option value="text">文本</option>
                <option value="hex">Hex</option>
              </select>
            </div>
          </div>
        </div>

        <div class="ck-card space-y-3 flex-1 overflow-y-auto">
          <p class="ck-section-title">密钥 & 参数</p>
          <div>
            <div class="flex items-center justify-between mb-1">
              <label class="ck-label !mb-0">密钥 (hex)</label>
              <button @click="genKey" class="text-xs text-violet-400 hover:text-violet-300">⚡ 生成</button>
            </div>
            <input v-model="aes.key" placeholder="输入hex格式密钥..." class="ck-input font-mono ck-trim-space" />
            <div v-if="aesKeyHint" :class="['mt-1 text-xs', hintClass(aesKeyHint)]">{{ aesKeyHint }}</div>
            <div v-if="aes.key" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (aes.key.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div v-if="!['ECB','GCM','CCM'].includes(aes.mode)">
            <div class="flex items-center justify-between mb-1">
              <label class="ck-label !mb-0">IV (hex)</label>
              <button @click="genIV" class="text-xs text-violet-400 hover:text-violet-300">⚡ 生成</button>
            </div>
            <input v-model="aes.iv" placeholder="留空则自动生成..." class="ck-input font-mono ck-trim-space" />
            <div v-if="aesIVHint" :class="['mt-1 text-xs', hintClass(aesIVHint)]">{{ aesIVHint }}</div>
            <div v-if="aes.iv" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (aes.iv.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div v-if="['GCM','CCM'].includes(aes.mode)">
            <div class="flex items-center justify-between mb-1">
              <label class="ck-label !mb-0">Nonce (hex)</label>
              <button @click="genNonce" class="text-xs text-violet-400 hover:text-violet-300">⚡ 生成</button>
            </div>
            <input v-model="aes.nonce" placeholder="留空则自动生成..." class="ck-input font-mono ck-trim-space" />
            <div v-if="aesNonceHint" :class="['mt-1 text-xs', hintClass(aesNonceHint)]">{{ aesNonceHint }}</div>
            <div v-if="aes.nonce" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (aes.nonce.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
            <div class="mt-2">
              <label class="ck-label">AAD (可选, hex)</label>
              <input v-model="aes.aad" placeholder="附加认证数据..." class="ck-input font-mono ck-trim-space" />
              <div v-if="aesAADHint" :class="['mt-1 text-xs', hintClass(aesAADHint)]">{{ aesAADHint }}</div>
              <div v-if="aes.aad" class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                  {{ (aes.aad.replace(/\s+/g, '').length / 2) + ' bytes' }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Middle: data + result -->
      <div class="space-y-3 flex flex-col min-h-0">
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="aes.plaintext" label="明文" :placeholder="aes.inputFormat === 'text' ? '输入明文...' : '输入hex格式数据...'"
                       clearable type="textarea" :rows="4" />
          <div v-if="aesLenHint" :class="['mt-1 text-xs', hintClass(aesLenHint)]">{{ aesLenHint }}</div>
        </div>
        <div class="flex gap-2 shrink-0">
          <button @click="encrypt" class="ck-btn-primary flex-1 justify-center" :disabled="aesDisabled">
            <LockIcon class="w-3.5 h-3.5" /> 加密
          </button>
          <button @click="decrypt" class="ck-btn-secondary flex-1 justify-center" :disabled="aesDisabled">
            <UnlockIcon class="w-3.5 h-3.5" /> 解密
          </button>
        </div>
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="result.data" label="结果 (hex)" type="result"
                       :success="result.success" copyable />
          <div v-if="result.extra" class="mt-2">
            <div class="flex items-center justify-between mb-1">
              <label class="ck-label !mb-0 text-amber-400">自动生成的 {{ ['GCM','CCM'].includes(aes.mode) ? 'Nonce' : 'IV' }}</label>
              <button @click="copyExtra" class="ck-copy-btn text-amber-400">
                <CopyIcon class="w-3 h-3" /> 复制
              </button>
            </div>
            <div class="ck-result !min-h-0 text-amber-300">{{ result.extra }}</div>
          </div>
          <div v-if="result.error" class="mt-2 text-xs text-red-400 flex items-center gap-1">
            <AlertCircleIcon class="w-3.5 h-3.5 shrink-0" /> {{ result.error }}
          </div>
        </div>
      </div>

      <!-- Right: mode principles -->
      <div class="ck-card flex flex-col min-h-0 overflow-y-auto ck-right-panel">
        <p class="ck-section-title">{{ aes.mode }} 模式原理</p>
        <div class="space-y-2 text-xs leading-relaxed flex-1" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
          <div class="p-2.5 rounded-lg border border-gray-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-semibold text-gray-400 mb-1">输入长度</p>
            <p>• Hex 输入长度需为偶数位</p>
            <p>• NoPadding 时必须是 16 字节的倍数</p>
            <p v-if="aes.inputFormat === 'text'">• 文本输入长度任意</p>
          </div>
          <div v-if="aes.mode === 'ECB'" class="space-y-2">
            <div class="p-2.5 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-violet-400 mb-1">电码本模式 (ECB)</p>
              <p>最简单的分组模式，每个明文块独立加密，产生独立密文块，块间无依赖关系。</p>
            </div>
            <div class="p-2.5 rounded-lg border border-red-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-red-400 mb-1">⚠️ 安全警告</p>
              <p>相同明文块总产生相同密文块，会泄露数据模式（如"企鹅效应"）。<strong class="text-red-300">不推荐用于实际加密。</strong></p>
            </div>
            <div class="p-2.5 rounded-lg border border-gray-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-gray-400 mb-1">参数</p>
              <p>• 无需 IV / Nonce</p>
              <p>• 需要 PKCS7 / Zero 填充</p>
              <p>• 支持并行加解密</p>
            </div>
          </div>

          <div v-if="aes.mode === 'CBC'" class="space-y-2">
            <div class="p-2.5 rounded-lg border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-emerald-400 mb-1">密文分组链模式 (CBC)</p>
              <p>每块明文与<strong class="text-emerald-300">前一密文块 XOR</strong> 后再加密。第一块与 IV 异或，引入随机性。</p>
            </div>
            <div class="p-2.5 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-blue-400 mb-1">特性</p>
              <p>• 安全性好，相同明文→不同密文</p>
              <p>• 串行加密，<strong class="text-blue-300">不可并行</strong></p>
              <p>• 一块错误会传播到后续所有块</p>
            </div>
            <div class="p-2.5 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-violet-400 mb-1">适用场景</p>
              <p>文件加密、数据库加密，是目前最常用的块加密模式之一。</p>
            </div>
          </div>

          <div v-if="aes.mode === 'CFB'" class="space-y-2">
            <div class="p-2.5 rounded-lg border border-cyan-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-cyan-400 mb-1">密文反馈模式 (CFB)</p>
              <p>将分组密码转化为<strong class="text-cyan-300">流密码</strong>。加密前一密文块产生的密钥流与明文 XOR。</p>
            </div>
            <div class="p-2.5 rounded-lg border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-emerald-400 mb-1">优势</p>
              <p>• 无需对明文填充</p>
              <p>• 适合流式加密（如网络传输）</p>
              <p>• 解密可并行，加密不可并行</p>
            </div>
          </div>

          <div v-if="aes.mode === 'OFB'" class="space-y-2">
            <div class="p-2.5 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-violet-400 mb-1">输出反馈模式 (OFB)</p>
              <p>产生独立于明文的<strong class="text-violet-300">伪随机密钥流</strong>，再与明文 XOR。密钥流可预先生成。</p>
            </div>
            <div class="p-2.5 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-blue-400 mb-1">特性</p>
              <p>• 位错误不扩散到其他位</p>
              <p>• 加解密均不可并行</p>
              <p>• 适合噪声信道（如卫星通信）</p>
            </div>
          </div>

          <div v-if="aes.mode === 'CTR'" class="space-y-2">
            <div class="p-2.5 rounded-lg border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-emerald-400 mb-1">计数器模式 (CTR)</p>
              <p>使用<strong class="text-emerald-300">递增计数器</strong>产生密钥流，与明文 XOR，将分组密码转化为流密码。</p>
            </div>
            <div class="p-2.5 rounded-lg border border-green-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-green-400 mb-1">优势</p>
              <p>• <strong class="text-green-300">完全可并行化</strong></p>
              <p>• 无需填充，支持随机访问</p>
              <p>• 现代首选的非认证模式</p>
            </div>
          </div>

          <div v-if="aes.mode === 'GCM'" class="space-y-2">
            <div class="p-2.5 rounded-lg border border-cyan-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-cyan-400 mb-1">Galois/计数器模式 (GCM)</p>
              <p><strong class="text-cyan-300">AEAD 认证加密模式</strong>：CTR 模式加密 + GMAC 伽罗瓦消息认证码。</p>
            </div>
            <div class="p-2.5 rounded-lg border border-green-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-green-400 mb-1">核心优势</p>
              <p>• 一次完成加密+认证，防篡改</p>
              <p>• 支持附加认证数据 (AAD)</p>
              <p>• 硬件加速支持 (AES-NI)</p>
              <p>• <strong class="text-green-300">TLS 1.3 / SSH 首选</strong></p>
            </div>
          </div>

          <div v-if="aes.mode === 'CCM'" class="space-y-2">
            <div class="p-2.5 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-violet-400 mb-1">CTR+CBC-MAC 模式 (CCM)</p>
              <p>CTR 模式加密 + CBC-MAC 认证，另一种 <strong class="text-violet-300">AEAD 模式</strong>。</p>
            </div>
            <div class="p-2.5 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-blue-400 mb-1">特性</p>
              <p>• 安全性与 GCM 相当</p>
              <p>• 需要预知消息长度</p>
              <p>• WiFi (802.11i) 和 IoT 常见</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- DES Tab -->
    <div v-if="activeTab === 'des'" class="grid grid-cols-3 gap-4 animate-fade-in h-full overflow-hidden">
      <!-- Left: params -->
      <div class="space-y-3 flex flex-col min-h-0 overflow-y-auto">
        <div class="ck-card">
          <p class="ck-section-title">算法参数</p>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="ck-label">算法类型</label>
              <select v-model="des.type" class="ck-select">
                <option value="DES">DES (56位)</option>
                <option value="3DES">3DES (168位)</option>
              </select>
            </div>
            <div>
              <label class="ck-label">加密模式</label>
              <select v-model="des.mode" class="ck-select">
                <option>ECB</option><option>CBC</option><option>CFB</option>
                <option>OFB</option><option>CTR</option>
              </select>
            </div>
            <div>
              <label class="ck-label">填充方式</label>
              <select v-model="des.padding" class="ck-select">
                <option>PKCS7</option><option>Zero</option><option>NoPadding</option>
              </select>
            </div>
          </div>
        </div>
        <div class="ck-card space-y-3 flex-1 overflow-y-auto">
          <p class="ck-section-title">密钥 & 参数</p>
          <div>
            <div class="flex justify-between mb-1">
              <label class="ck-label !mb-0">密钥 (hex)</label>
              <button @click="genDesKey" class="text-xs text-violet-400 hover:text-violet-300">⚡ 生成</button>
            </div>
            <input v-model="des.key" :placeholder="des.type === '3DES' ? '48位Hex (24字节)' : '16位Hex (8字节)'" class="ck-input font-mono ck-trim-space" />
            <div v-if="desKeyHint" :class="['mt-1 text-xs', hintClass(desKeyHint)]">{{ desKeyHint }}</div>
            <div v-if="des.key" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (des.key.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div v-if="des.mode !== 'ECB'">
            <div class="flex justify-between mb-1">
              <label class="ck-label !mb-0">IV (hex)</label>
              <button @click="genDesIV" class="text-xs text-violet-400 hover:text-violet-300">⚡ 生成</button>
            </div>
            <input v-model="des.iv" placeholder="16位Hex (8字节)" class="ck-input font-mono ck-trim-space" />
            <div v-if="desIVHint" :class="['mt-1 text-xs', hintClass(desIVHint)]">{{ desIVHint }}</div>
          </div>
        </div>
      </div>

      <!-- Middle: data + result -->
      <div class="space-y-3 flex flex-col min-h-0">
        <div class="ck-card flex-1 min-h-0">
          <CryptoPanel v-model="des.plaintext" label="明文 (hex)" clearable type="textarea" :rows="5" />
          <div v-if="desLenHint" :class="['mt-1 text-xs', hintClass(desLenHint)]">{{ desLenHint }}</div>
        </div>
        <div class="flex gap-2 shrink-0">
          <button @click="desEncrypt" class="ck-btn-primary flex-1 justify-center" :disabled="desDisabled"><LockIcon class="w-3.5 h-3.5" /> 加密</button>
          <button @click="desDecrypt" class="ck-btn-secondary flex-1 justify-center" :disabled="desDisabled"><UnlockIcon class="w-3.5 h-3.5" /> 解密</button>
        </div>
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="desResult.data" label="结果 (hex)" type="result" :success="desResult.success" copyable />
          <div v-if="desResult.error" class="mt-2 text-xs text-red-400">{{ desResult.error }}</div>
        </div>
      </div>

      <!-- Right: DES principles -->
      <div class="ck-card flex flex-col min-h-0 overflow-y-auto ck-right-panel">
        <p class="ck-section-title">{{ des.type }} 算法原理</p>
        <div class="space-y-2 text-xs leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
          <div class="p-2.5 rounded-lg border border-gray-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-semibold text-gray-400 mb-1">输入长度</p>
            <p>• Hex 输入长度需为偶数位</p>
            <p>• NoPadding 时必须是 8 字节的倍数</p>
          </div>
          <div class="p-2.5 rounded-lg border border-amber-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-semibold text-amber-400 mb-1">{{ des.type === '3DES' ? '三重DES (3DES/TDEA)' : '数据加密标准 (DES)' }}</p>
            <p v-if="des.type === 'DES'">IBM 于 1975 年设计，1977 年成为美国联邦标准。Feistel 网络结构，16轮迭代。</p>
            <p v-else>在 DES 基础上三次应用: 加密 → 解密 → 加密 (EDE)，有效密钥长度112或168位。</p>
          </div>
          <div class="p-2.5 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-semibold text-blue-400 mb-1">技术参数</p>
            <p>• 分组长度: 64 位 (8 字节)</p>
            <p v-if="des.type === 'DES'">• 密钥长度: 64 位 (8 字节, 有效56位)</p>
            <p v-else>• 密钥长度: 192 位 (24 字节, 有效112/168位)</p>
            <p>• 结构: Feistel 网络 ({{ des.type === '3DES' ? '48' : '16' }}轮)</p>
          </div>
          <div class="p-2.5 rounded-lg border border-red-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-semibold text-red-400 mb-1">⚠️ 安全注意</p>
            <p v-if="des.type === 'DES'"><strong class="text-red-300">DES 已不安全</strong>，56位密钥可在数小时内暴力破解。仅用于学习和遗留系统兼容。</p>
            <p v-else>3DES 安全性尚可，但性能差，已逐渐被 <strong class="text-amber-300">AES</strong> 取代。NIST 于2023年正式弃用。</p>
          </div>
          <div class="p-2.5 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-semibold text-violet-400 mb-1">Feistel 结构</p>
            <p>将64位数据分为左右32位，每轮将右半部分经过 F 函数和子密钥运算后与左半部分 XOR，再交换左右，保证可逆性。</p>
          </div>
          <div class="p-2.5 rounded-lg border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-semibold text-emerald-400 mb-1">{{ des.mode }} 模式</p>
            <p v-if="des.mode === 'ECB'">电码本模式：每块独立加密，<span class="text-red-300">不推荐</span>。</p>
            <p v-else-if="des.mode === 'CBC'">密文链模式：前一密文块参与当前块加密，需要 IV，安全性好。</p>
            <p v-else-if="des.mode === 'CFB'">密文反馈模式：将分组密码变为流密码，无需填充。</p>
            <p v-else-if="des.mode === 'OFB'">输出反馈模式：产生独立密钥流，错误不扩散。</p>
            <p v-else-if="des.mode === 'CTR'">计数器模式：可并行计算，现代推荐非认证模式。</p>
          </div>
        </div>
      </div>
    </div>

    <!-- ChaCha20 Tab -->
    <div v-if="activeTab === 'chacha'" class="grid grid-cols-3 gap-4 animate-fade-in h-full overflow-hidden">
      <!-- Left: params -->
      <div class="space-y-3 flex flex-col min-h-0 overflow-y-auto">
        <div class="ck-card">
          <p class="ck-section-title">算法参数</p>
          <div>
            <label class="ck-label">算法类型</label>
            <select v-model="chacha.type" class="ck-select">
              <option value="ChaCha20">ChaCha20</option>
              <option value="XChaCha20">XChaCha20</option>
              <option value="ChaCha20-Poly1305">ChaCha20-Poly1305 (AEAD)</option>
              <option value="XChaCha20-Poly1305">XChaCha20-Poly1305 (AEAD)</option>
            </select>
          </div>
        </div>
        <div class="ck-card space-y-3 flex-1 overflow-y-auto">
          <p class="ck-section-title">密钥 & 参数</p>
          <div>
            <div class="flex justify-between mb-1">
              <label class="ck-label !mb-0">密钥 (hex, 32字节)</label>
              <button @click="genChaChaKey" class="text-xs text-violet-400 hover:text-violet-300">⚡ 生成</button>
            </div>
            <input v-model="chacha.key" placeholder="64位hex (32字节)..." class="ck-input font-mono ck-trim-space" />
            <div v-if="chachaKeyHint" :class="['mt-1 text-xs', hintClass(chachaKeyHint)]">{{ chachaKeyHint }}</div>
            <div v-if="chacha.key" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (chacha.key.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div>
            <div class="flex justify-between mb-1">
              <label class="ck-label !mb-0">Nonce (hex)</label>
              <button @click="genChachaNonce" class="text-xs text-violet-400 hover:text-violet-300">⚡ 生成</button>
            </div>
            <input v-model="chacha.nonce" :placeholder="chacha.type.startsWith('X') ? '48位Hex (24字节)' : '24位Hex (12字节)'" class="ck-input font-mono ck-trim-space" />
            <div v-if="chachaNonceHint" :class="['mt-1 text-xs', hintClass(chachaNonceHint)]">{{ chachaNonceHint }}</div>
            <div v-if="chacha.nonce" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (chacha.nonce.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div v-if="chacha.type.includes('Poly1305')">
            <label class="ck-label">AAD (可选, hex)</label>
            <input v-model="chacha.aad" placeholder="附加认证数据..." class="ck-input font-mono ck-trim-space" />
            <div v-if="chachaAADHint" :class="['mt-1 text-xs', hintClass(chachaAADHint)]">{{ chachaAADHint }}</div>
            <div v-if="chacha.aad" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (chacha.aad.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Middle: data + result -->
      <div class="space-y-3 flex flex-col min-h-0">
        <div class="ck-card flex-1 min-h-0">
          <CryptoPanel v-model="chacha.data" label="数据 (hex)" clearable type="textarea" :rows="5" />
          <div v-if="chachaLenHint" :class="['mt-1 text-xs', hintClass(chachaLenHint)]">{{ chachaLenHint }}</div>
        </div>
        <div class="flex gap-2 shrink-0">
          <button @click="chachaEncrypt" class="ck-btn-primary flex-1 justify-center" :disabled="chachaDisabled"><LockIcon class="w-3.5 h-3.5" /> 加密</button>
          <button @click="chachaDecrypt" class="ck-btn-secondary flex-1 justify-center" :disabled="chachaDisabled"><UnlockIcon class="w-3.5 h-3.5" /> 解密</button>
        </div>
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="chachaResult.data" label="结果 (hex)" type="result" :success="chachaResult.success" copyable />
          <div v-if="chachaResult.extra" class="mt-2 text-xs text-amber-400">自动生成 Nonce: {{ chachaResult.extra }}</div>
          <div v-if="chachaResult.error" class="mt-2 text-xs text-red-400">{{ chachaResult.error }}</div>
        </div>
      </div>

      <!-- Right: ChaCha20 principles -->
      <div class="ck-card flex flex-col min-h-0 overflow-y-auto ck-right-panel">
        <p class="ck-section-title">{{ chacha.type }} 算法原理</p>
        <div class="space-y-2 text-xs leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
          <div class="p-2.5 rounded-lg border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-semibold text-emerald-400 mb-1">ChaCha20 流密码</p>
            <p>由 Daniel J. Bernstein 设计。基于 <strong class="text-emerald-300">ARX 操作</strong>（加法-旋转-异或），纯软件实现极快。</p>
          </div>
          <div class="p-2.5 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-semibold text-blue-400 mb-1">核心参数</p>
            <p>• 密钥: 256 位 (32 字节)</p>
            <p v-if="chacha.type.startsWith('X')">• Nonce: 192 位 (24 字节, 扩展版)</p>
            <p v-else>• Nonce: 96 位 (12 字节)</p>
            <p>• 计数器: 32 位 (每块递增)</p>
            <p>• 块大小: 512 位 (64 字节)</p>
            <p>• 输入数据长度: 任意字节 (Hex 需偶数位)</p>
          </div>
          <div class="p-2.5 rounded-lg border border-cyan-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-semibold text-cyan-400 mb-1">Quarter Round 函数</p>
            <p>核心是 20 轮 Quarter Round (4次ARX运算)，对4个32位字进行混淆扩散，确保雪崩效应。</p>
          </div>
          <div v-if="chacha.type.includes('Poly1305')" class="p-2.5 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-semibold text-violet-400 mb-1">Poly1305 认证 (AEAD)</p>
            <p>组合使用一次性消息认证码 Poly1305，提供加密+完整性认证，防篡改。<strong class="text-violet-300">RFC 8439 标准</strong>，TLS/SSH 广泛使用。</p>
          </div>
          <div v-if="chacha.type.startsWith('X')" class="p-2.5 rounded-lg border border-amber-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-semibold text-amber-400 mb-1">XChaCha20 扩展版</p>
            <p>将 Nonce 从 96 位扩展至 <strong class="text-amber-300">192 位</strong>，极大降低随机 Nonce 碰撞概率，适合大规模随机加密场景。</p>
          </div>
          <div class="p-2.5 rounded-lg border border-green-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-semibold text-green-400 mb-1">优势</p>
            <p>• 无需 AES 硬件指令，抗侧信道攻击</p>
            <p>• 可完全并行计算，高性能</p>
            <p>• Google 推动其成为 TLS 1.3 标准算法</p>
          </div>
        </div>
      </div>
    </div>

    <!-- RC4 Tab -->
    <div v-if="activeTab === 'rc4'" class="grid grid-cols-2 gap-4 animate-fade-in h-full overflow-hidden">
      <div class="space-y-3 overflow-y-auto pr-1">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">RC4 参数</p>
          <div>
            <div class="flex items-center justify-between mb-1">
              <label class="ck-label !mb-0">密钥 (hex)</label>
              <button @click="genRC4Key" class="text-xs text-violet-400 hover:text-violet-300">⚡ 生成</button>
            </div>
            <input v-model="rc4.key" class="ck-input font-mono ck-trim-space" placeholder="1-256字节 Hex" />
            <div v-if="rc4KeyHint" :class="['mt-1 text-xs', hintClass(rc4KeyHint)]">{{ rc4KeyHint }}</div>
            <div v-if="rc4.key" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (rc4.key.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="rc4.data" label="数据 (hex)" type="textarea" :rows="5" clearable />
          <div v-if="rc4LenHint" :class="['mt-1 text-xs', hintClass(rc4LenHint)]">{{ rc4LenHint }}</div>
        </div>
        <div class="flex gap-2">
          <button @click="rc4Encrypt" class="ck-btn-primary flex-1 justify-center" :disabled="rc4Disabled">
            <LockIcon class="w-3.5 h-3.5" /> RC4 加密
          </button>
          <button @click="rc4Decrypt" class="ck-btn-secondary flex-1 justify-center" :disabled="rc4Disabled">
            <UnlockIcon class="w-3.5 h-3.5" /> RC4 解密
          </button>
        </div>
      </div>

      <div class="space-y-3 ck-right-panel flex flex-col min-h-0">
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="rc4Result.data" label="结果 (hex)" type="result" :success="rc4Result.success" copyable />
          <div v-if="rc4Result.error" class="mt-2 text-xs text-red-400">{{ rc4Result.error }}</div>
        </div>
        <div class="ck-card flex-1 overflow-y-auto">
          <p class="ck-section-title">说明</p>
          <div class="text-xs space-y-2" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <p>• RC4 为流密码，加密解密过程相同。</p>
            <p>• 不建议用于新系统，仅作兼容性/学习用途。</p>
            <p>• 输入数据长度任意 (Hex 需偶数位)。</p>
          </div>
        </div>
      </div>
    </div>

    <!-- SIV Tab -->
    <div v-if="activeTab === 'siv'" class="grid grid-cols-2 gap-4 animate-fade-in h-full overflow-hidden">
      <div class="space-y-3 overflow-y-auto pr-1">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">AES-SIV 参数</p>
          <div>
            <label class="ck-label">模式</label>
            <select v-model="siv.mode" class="ck-select">
              <option value="AES-SIV">AES-SIV (RFC 5297)</option>
              <option value="AES-GCM-SIV">AES-GCM-SIV</option>
            </select>
          </div>
          <div>
            <div class="flex items-center justify-between mb-1">
              <label class="ck-label !mb-0">密钥 (hex)</label>
              <button @click="genSIVKey" class="text-xs text-violet-400 hover:text-violet-300">⚡ 生成</button>
            </div>
            <input v-model="siv.key" class="ck-input font-mono ck-trim-space"
                   :placeholder="siv.mode === 'AES-SIV' ? '64/96/128位Hex (32/48/64字节)' : '32/64位Hex (16/32字节)'" />
            <div v-if="sivKeyHint" :class="['mt-1 text-xs', hintClass(sivKeyHint)]">{{ sivKeyHint }}</div>
            <div v-if="siv.key" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (siv.key.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div>
            <label class="ck-label">Nonce (hex)</label>
            <input v-model="siv.nonce" class="ck-input font-mono ck-trim-space"
                   :placeholder="siv.mode === 'AES-SIV' ? '可选 32位Hex (16字节) 或留空' : '必须 24位Hex (12字节)'" />
            <div v-if="sivNonceHint" :class="['mt-1 text-xs', hintClass(sivNonceHint)]">{{ sivNonceHint }}</div>
            <div v-if="siv.nonce" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (siv.nonce.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div>
            <label class="ck-label">AAD (可选, hex)</label>
            <input v-model="siv.aad" class="ck-input font-mono ck-trim-space" placeholder="附加认证数据..." />
            <div v-if="sivAADHint" :class="['mt-1 text-xs', hintClass(sivAADHint)]">{{ sivAADHint }}</div>
            <div v-if="siv.aad" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (siv.aad.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="siv.data" label="数据 (hex)" type="textarea" :rows="5" clearable />
          <div v-if="sivLenHint" :class="['mt-1 text-xs', hintClass(sivLenHint)]">{{ sivLenHint }}</div>
        </div>
        <div class="flex gap-2">
          <button @click="sivEncrypt" class="ck-btn-primary flex-1 justify-center" :disabled="sivDisabled">
            <LockIcon class="w-3.5 h-3.5" /> 加密
          </button>
          <button @click="sivDecrypt" class="ck-btn-secondary flex-1 justify-center" :disabled="sivDisabled">
            <UnlockIcon class="w-3.5 h-3.5" /> 解密
          </button>
        </div>
      </div>

      <div class="space-y-3 ck-right-panel flex flex-col min-h-0">
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="sivResult.data" label="结果 (hex)" type="result" :success="sivResult.success" copyable />
          <div v-if="sivResult.error" class="mt-2 text-xs text-red-400">{{ sivResult.error }}</div>
        </div>
        <div class="ck-card flex-1 overflow-y-auto">
          <p class="ck-section-title">说明</p>
          <div class="text-xs space-y-2" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <p>• AES-SIV / AES-GCM-SIV 为抗 Nonce 复用的 AEAD。</p>
            <p>• AES-SIV 支持空 Nonce，AES-GCM-SIV 需 12 字节 Nonce。</p>
            <p>• 输入数据长度任意 (Hex 需偶数位)。</p>
          </div>
        </div>
      </div>
    </div>

    <!-- FPE Tab -->
    <div v-if="activeTab === 'fpe'" class="grid grid-cols-2 gap-4 animate-fade-in h-full overflow-hidden">
      <div class="space-y-3 overflow-y-auto pr-1">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">FPE 参数</p>
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="ck-label">算法</label>
              <select v-model="fpe.cipher" class="ck-select">
                <option value="AES">AES</option>
                <option value="SM4">SM4</option>
              </select>
            </div>
            <div>
              <label class="ck-label">模式</label>
              <select v-model="fpe.mode" class="ck-select">
                <option value="FF1">FF1</option>
                <option value="FF3-1">FF3-1</option>
              </select>
            </div>
            <div>
              <label class="ck-label">字符集</label>
              <select v-model="fpe.alphabetMode" class="ck-select">
                <option value="digits">数字 (0-9)</option>
                <option value="hex">Hex (0-9A-F)</option>
                <option value="alnum">数字+大写字母</option>
                <option value="custom">自定义</option>
              </select>
            </div>
          </div>
          <div v-if="fpe.alphabetMode === 'custom'">
            <label class="ck-label">自定义字符集</label>
            <input v-model="fpe.alphabetCustom" class="ck-input font-mono ck-trim-space" placeholder="例如: ABCDEF0123" />
          </div>
          <div>
            <div class="flex items-center justify-between mb-1">
              <label class="ck-label !mb-0">密钥 (hex)</label>
              <button @click="genFPEKey" class="text-xs text-violet-400 hover:text-violet-300">⚡ 生成</button>
            </div>
            <input v-model="fpe.key" class="ck-input font-mono ck-trim-space" :placeholder="fpe.cipher === 'SM4' ? '32位Hex (16字节)' : '32/48/64位Hex (16/24/32字节)'" />
            <div v-if="fpeKeyHint" :class="['mt-1 text-xs', hintClass(fpeKeyHint)]">{{ fpeKeyHint }}</div>
            <div v-if="fpe.key" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (fpe.key.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div>
            <label class="ck-label">Tweak (hex, 可选)</label>
            <input v-model="fpe.tweak" class="ck-input font-mono ck-trim-space"
                   :placeholder="fpe.mode === 'FF3-1' ? 'FF3-1需要14位Hex(7字节)，留空默认全0' : '留空则不使用'" />
            <div v-if="fpeTweakHint" :class="['mt-1 text-xs', hintClass(fpeTweakHint)]">{{ fpeTweakHint }}</div>
            <div v-if="fpe.tweak" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (fpe.tweak.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="fpe.data" label="待处理数据" type="textarea" :rows="4" clearable />
          <div v-if="fpeLenHint" :class="['mt-1 text-xs', hintClass(fpeLenHint)]">{{ fpeLenHint }}</div>
        </div>
        <div class="flex gap-2">
          <button @click="fpeEncrypt" class="ck-btn-primary flex-1 justify-center" :disabled="fpeDisabled">
            <LockIcon class="w-3.5 h-3.5" /> FPE 加密
          </button>
          <button @click="fpeDecrypt" class="ck-btn-secondary flex-1 justify-center" :disabled="fpeDisabled">
            <UnlockIcon class="w-3.5 h-3.5" /> FPE 解密
          </button>
        </div>
      </div>

      <div class="space-y-3 ck-right-panel flex flex-col min-h-0">
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="fpeResult.data" label="结果" type="result" :success="fpeResult.success" copyable />
          <div v-if="fpeResult.error" class="mt-2 text-xs text-red-400">{{ fpeResult.error }}</div>
        </div>
        <div class="ck-card flex-1 overflow-y-auto">
          <p class="ck-section-title">说明</p>
          <div class="text-xs space-y-2" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <p>• FPE 会保持数据格式不变，例如银行卡号加密后仍是同长度数字。</p>
            <p>• 字符集必须与数据匹配，不能包含重复字符。</p>
            <p>• FF1/FF3-1 均为 NIST 标准模式，FF3-1 使用 7 字节 Tweak。</p>
            <p>• AES 支持 16/24/32 字节密钥，SM4 固定 16 字节密钥。</p>
            <p>• 输入长度: ≥ {{ fpeMinLen }}；最大 {{ fpeMaxLen }}</p>
          </div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { storeToRefs } from 'pinia'
import { LockIcon, UnlockIcon, CopyIcon, AlertCircleIcon } from 'lucide-vue-next'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import { AESEncrypt, AESDecrypt, DESEncrypt, DESDecrypt, ChaCha20Encrypt, ChaCha20Decrypt, RC4Encrypt, RC4Decrypt, SIVEncrypt, SIVDecrypt, FPEEncrypt, FPEDecrypt } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'aes', label: 'AES' },
  { id: 'des', label: 'DES / 3DES' },
  { id: 'chacha', label: 'ChaCha20' },
  { id: 'siv', label: 'AES-SIV' },
  { id: 'rc4', label: 'RC4' },
  { id: 'fpe', label: 'FPE' },
]
const activeTab = ref('aes')

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
    if (r.success) store.addHistory({ algorithm: `AES-${aes.keySize}-${aes.mode}`, result: r.data })
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
async function copyExtra() {
  if (!result.extra) return
  await navigator.clipboard.writeText(result.extra)
  store.showToast('已复制')
}

// DES state
const des = reactive({ type: 'DES', mode: 'CBC', padding: 'PKCS7', key: '', iv: '', plaintext: '' })
const desResult = reactive({ data: '', error: '', success: null })

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
  return 'text-amber-400'
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
