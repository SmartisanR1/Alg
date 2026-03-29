<template>
  <PageLayout title="国密算法" subtitle="SM2 · SM3 · SM4 · SM9 · ZUC (祖冲之)"
              icon-bg="bg-red-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <FlagIcon class="w-4 h-4 text-emerald-400" />
    </template>

    <template #extra>
      <button @click="showPrinciple = true" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-violet-500/10 text-violet-400 hover:bg-violet-500/20 transition-all text-xs font-medium border border-violet-500/20">
        <InfoIcon class="w-3.5 h-3.5" /> 算法原理
      </button>
    </template>

    <!-- Principle Modal -->
    <transition name="fade">
      <div v-if="showPrinciple" class="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" @click.self="showPrinciple = false">
        <div class="ck-card max-w-lg w-full shadow-2xl animate-in zoom-in-95 duration-200" :class="isDark ? 'bg-dark-card border-dark-border' : 'bg-white border-gray-200'">
          <div class="flex justify-between items-center mb-4 border-b pb-3" :class="isDark ? 'border-dark-border' : 'border-gray-100'">
            <h3 class="text-sm font-bold flex items-center gap-2">
              <InfoIcon class="w-4 h-4 text-violet-400" /> {{ currentPrinciple.title }}
            </h3>
            <button @click="showPrinciple = false" class="p-1 hover:bg-gray-100 dark:hover:bg-dark-hover rounded-md transition-colors">
              <XIcon class="w-4 h-4 text-dark-muted" />
            </button>
          </div>
          <div class="text-xs leading-relaxed space-y-3" :class="isDark ? 'text-dark-muted' : 'text-gray-600'">
            <p v-for="(p, i) in currentPrinciple.content.split('\n')" :key="i">{{ p }}</p>
          </div>
          <div class="mt-6 flex justify-end">
            <button @click="showPrinciple = false" class="ck-btn-primary px-6">确定</button>
          </div>
        </div>
      </div>
    </transition>

    <!-- SM2 -->
    <div v-if="activeTab === 'sm2'" class="grid grid-cols-2 gap-4 animate-fade-in h-full overflow-hidden">
      <div class="space-y-4 flex flex-col min-h-0">
        <!-- Sub-tabs -->
        <div class="flex gap-1 p-1 rounded-lg w-fit shrink-0"
             :class="isDark ? 'bg-dark-card' : 'bg-light-card'">
          <button v-for="s in sm2Subtabs" :key="s.id"
                  class="px-3 py-1 rounded-md text-xs font-medium transition-all"
                  :class="sm2Sub === s.id ? (isDark ? 'bg-dark-accent text-white' : 'bg-light-accent text-white') : (isDark ? 'text-dark-muted hover:text-dark-text' : 'text-light-muted hover:text-light-text')"
                  @click="sm2Sub = s.id">
            {{ s.label }}
          </button>
        </div>

        <!-- Key Gen -->
        <div v-if="sm2Sub === 'keygen'" class="ck-card flex flex-col flex-1 min-h-0">
          <p class="ck-section-title">SM2 密钥对生成</p>
          <p class="text-[11px] mb-4" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            基于国密 SM2 椭圆曲线 (256位), 符合 GM/T 0003 规范
          </p>
          <div class="flex gap-2 mb-4">
            <select v-model="sm2KeyFormat" class="ck-select flex-1">
              <option value="pem">PEM 格式</option>
              <option value="hex">HEX 格式</option>
            </select>
            <button @click="genSM2Key" class="ck-btn-primary flex-1 justify-center">
              <KeyIcon class="w-3.5 h-3.5" /> 生成SM2密钥对
            </button>
          </div>
          <div v-if="sm2Keys.privateKey" class="space-y-3 flex-1 overflow-y-auto pr-1">
            <div>
              <div class="flex justify-between mb-1">
                <label class="ck-label !mb-0 text-amber-400">私钥 ({{ sm2KeyFormat.toUpperCase() }})</label>
                <button @click="copy(sm2KeyFormat === 'pem' ? sm2Keys.privateKey : sm2Keys.privHex)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="ck-result ck-key-hex !min-h-0 text-amber-300 !text-[11px] break-all max-h-40 overflow-y-auto font-mono">
                {{ sm2KeyFormat === 'pem' ? sm2Keys.privateKey : sm2Keys.privHex }}
              </div>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="ck-label !mb-0 text-cyan-400">公钥 ({{ sm2KeyFormat.toUpperCase() }})</label>
                <button @click="copy(sm2KeyFormat === 'pem' ? sm2Keys.publicKey : sm2Keys.pubHex)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="ck-result ck-key-hex !min-h-0 text-cyan-300 !text-[11px] break-all max-h-32 overflow-y-auto font-mono">
                {{ sm2KeyFormat === 'pem' ? sm2Keys.publicKey : sm2Keys.pubHex }}
              </div>
            </div>
            <!-- Byte count badges below keys -->
            <div v-if="sm2Keys.privateKey" class="flex gap-3 mt-1 mb-2">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                私钥 {{ sm2KeyFormat === 'hex' ? (sm2Keys.privHex.length / 2) + ' bytes' : (sm2Keys.privateKey.split('\n').length + ' lines') }}
              </span>
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-cyan-400 border-cyan-500/20 bg-cyan-500/5">
                公钥 {{ sm2KeyFormat === 'hex' ? (sm2Keys.pubHex.length / 2) + ' bytes' : (sm2Keys.publicKey.split('\n').length + ' lines') }}
              </span>
            </div>
          </div>
        </div>

        <!-- Encrypt/Decrypt Inner -->
        <div v-if="sm2Sub === 'enc'" class="flex flex-col flex-1 min-h-0 space-y-3">
          <div class="ck-card space-y-3 overflow-y-auto pr-1">
            <CryptoPanel v-model="sm2Enc.publicKey" label="公钥 (PEM/Hex) — 用于加密" type="textarea" :rows="sm2KeyFormat === 'hex' ? 2 : 4" clearable />
            <CryptoPanel v-model="sm2Enc.privateKey" label="私钥 (PEM/Hex) — 用于解密" type="textarea" :rows="sm2KeyFormat === 'hex' ? 2 : 4" clearable />
          </div>
          <div class="ck-card shrink-0">
            <CryptoPanel v-model="sm2Enc.data" label="数据 (Hex)" type="textarea" :rows="3" clearable />
          </div>
          <div class="flex gap-2 shrink-0">
            <button @click="sm2Encrypt" class="ck-btn-primary flex-1 justify-center"><LockIcon class="w-3.5 h-3.5" />SM2加密</button>
            <button @click="sm2Decrypt" class="ck-btn-secondary flex-1 justify-center"><UnlockIcon class="w-3.5 h-3.5" />SM2解密</button>
          </div>
          <div class="ck-card shrink-0">
            <div class="flex justify-between items-center mb-2">
              <label class="ck-label !mb-0">结果 (Hex)</label>
              <button v-if="sm2EncResult.data" @click="copy(sm2EncResult.data)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" />复制</button>
            </div>
            <div class="ck-result" :class="sm2EncResult.success === true ? 'text-emerald-400' : sm2EncResult.success === false ? 'text-red-400' : ''">
              <span v-if="sm2EncResult.data">{{ sm2EncResult.data }}</span>
              <span v-else class="opacity-30">SM2 加密结果将显示在这里 (C1C3C2 格式 Hex)</span>
            </div>
            <div v-if="sm2EncResult.error" class="mt-2 text-xs text-red-400">{{ sm2EncResult.error }}</div>
          </div>
        </div>

        <!-- Sign/Verify Inner -->
        <div v-if="sm2Sub === 'sign'" class="flex flex-col flex-1 min-h-0 space-y-3">
          <div class="ck-card space-y-3 overflow-y-auto pr-1">
            <CryptoPanel v-model="sm2Sign.privateKey" label="私钥 (PEM/Hex) — 用于签名" type="textarea" :rows="sm2KeyFormat === 'hex' ? 2 : 4" clearable />
            <CryptoPanel v-model="sm2Sign.publicKey" label="公钥 (PEM/Hex) — 用于验签" type="textarea" :rows="sm2KeyFormat === 'hex' ? 2 : 4" clearable />
            <div>
              <label class="ck-label">用户标识 (IDA / 可选)</label>
              <input v-model="sm2Sign.id" placeholder="默认: 1234567812345678" class="ck-input" />
            </div>
          </div>
          <div class="ck-card shrink-0">
            <CryptoPanel v-model="sm2Sign.data" label="待处理数据 (Hex)" type="textarea" :rows="3" clearable />
          </div>
          <div class="flex gap-2 shrink-0">
            <button @click="doSM2Sign" class="ck-btn-primary flex-1 justify-center"><PenIcon class="w-3.5 h-3.5" />SM2签名</button>
            <button @click="doSM2Verify" class="ck-btn-secondary flex-1 justify-center"><CheckCircleIcon class="w-3.5 h-3.5" />SM2验签</button>
          </div>
          <div class="ck-card shrink-0">
            <div class="flex justify-between items-center mb-2">
              <label class="ck-label !mb-0">签名结果 (Hex)</label>
              <button v-if="sm2SignResult.data && sm2SignResult.data !== 'true'" @click="copy(sm2SignResult.data)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" />复制</button>
            </div>
            <div class="ck-result" :class="sm2SignResult.success === true ? (sm2SignResult.data === 'true' ? 'text-emerald-400' : 'text-cyan-300') : sm2SignResult.success === false ? 'text-red-400' : ''">
              <span v-if="sm2SignResult.data">{{ sm2SignResult.data === 'true' ? '✅ 签名验证通过' : sm2SignResult.data }}</span>
              <span v-else class="opacity-30">SM2 签名结果将显示在这里 (DER 格式 Hex)</span>
            </div>
            <div v-if="sm2SignResult.error" class="mt-2 text-xs" :class="sm2SignResult.data === 'true' ? 'text-emerald-400' : 'text-red-400'">{{ sm2SignResult.error }}</div>
          </div>
        </div>
      </div>

      <!-- Right Column: Principle Panel (Persistent) -->
      <div class="ck-card overflow-y-auto flex flex-col h-full ck-right-panel">
        <p class="ck-section-title">算法原理 (SM2)</p>
        <div class="space-y-3 text-[11px] leading-relaxed flex-1" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
          <div class="p-3 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-1 text-violet-400">设计规范</p>
            <p>• 标准: GM/T 0003-2012 / GB/T 32918-2016</p>
            <p>• 曲线参数: sm2p256v1 (素数域 256位 椭圆曲线)</p>
          </div>
          <div class="p-3 rounded-lg border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-1 text-emerald-400">核心流程</p>
            <p>1. 密钥对生成: 选取随机数 d 作为私钥, 计算 P = dG 作为公钥。</p>
            <p>2. 加密过程: 随机数 k -> 计算 C1=[k]G, C2=M⊕Hash(x2,y2), C3=Hash(x2,M,y2)。</p>
            <p>3. 签名过程: 计算 e=Hash(ZA, M), 随机数 k -> 计算 r=(e+x1)mod n, s=((1+d)^-1 * (k-rd))mod n。</p>
          </div>
          <div class="p-3 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-1 text-blue-400">安全性优势</p>
            <p>• 安全强度: 256位 SM2 相当于 3072位 RSA。</p>
            <p>• 抗攻击性: 具有更好的抗离散对数攻击能力，且无 RSA 存在的特定攻击风险。</p>
          </div>
        </div>
      </div>
    </div>

    <!-- SM3 -->
    <div v-if="activeTab === 'sm3'" class="grid grid-cols-2 gap-4 animate-fade-in h-full overflow-hidden">
      <div class="space-y-3 overflow-y-auto pr-1">
        <div class="ck-card">
          <label class="ck-label">输入格式</label>
          <select v-model="sm3Format" class="ck-select mb-3">
            <option value="text">纯文本 (UTF-8)</option>
            <option value="hex">十六进制 (Hex)</option>
          </select>
          <CryptoPanel v-model="sm3Data" label="输入数据" type="textarea" :rows="6" clearable />
        </div>
        <div class="flex gap-2">
          <button @click="computeSM3" class="ck-btn-primary flex-1 justify-center"><HashIcon class="w-3.5 h-3.5" />SM3 杂凑计算</button>
          <button @click="computeSM3HMAC" class="ck-btn-secondary flex-1 justify-center">SM3-HMAC</button>
        </div>
        <div v-if="sm3Sub === 'hmac'" class="ck-card animate-in slide-in-from-top-2 duration-200">
          <div class="flex justify-between mb-1">
            <label class="ck-label !mb-0">HMAC 密钥 (Hex)</label>
            <button @click="genSM3Key" class="text-xs text-violet-400">⚡ 随机生成</button>
          </div>
          <input v-model="sm3Key" class="ck-input font-mono ck-trim-space" placeholder="输入 16/32 字节 Hex 密钥..." />
        </div>
      </div>
      <div class="space-y-3 flex flex-col min-h-0 overflow-hidden h-full ck-right-panel">
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="sm3Result.data" label="SM3 杂凑值 (256-bit)" type="result" :success="sm3Result.success" copyable />
          <div v-if="sm3Result.error" class="mt-2 text-xs text-red-400">{{ sm3Result.error }}</div>
        </div>
        <div class="ck-card flex-1 overflow-y-auto">
          <p class="ck-section-title">算法原理 & 特性 (SM3)</p>
          <div class="text-[11px] space-y-3 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-3 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-violet-400">设计规范</p>
              <p>• 标准: GM/T 0004-2012 / GB/T 32905-2016</p>
              <p>• 输出长度: 256位 (32字节)</p>
              <p>• 输入长度: 任意字节 (Hex 需偶数位)</p>
            </div>
            <div class="p-3 rounded-lg border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-emerald-400">算法结构</p>
              <p>• 迭代结构: Merkle-Damgård 结构。</p>
              <p>• 消息分组: 512位 (64字节)。</p>
              <p>• 压缩函数: 包含消息填充、消息扩展和迭代压缩三个阶段。</p>
            </div>
            <div class="p-3 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-blue-400">安全性</p>
              <p>• SM3 的设计安全性与 SHA-256 相当，但在压缩函数的设计上采用了更复杂的非线性变换，具有更高的抗攻击余量。</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- SM4 -->
    <div v-if="activeTab === 'sm4'" class="grid grid-cols-2 gap-4 animate-fade-in h-full overflow-hidden">
      <div class="space-y-3 overflow-y-auto pr-1">
        <div class="ck-card">
          <p class="ck-section-title">算法参数配置</p>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="ck-label">工作模式</label>
              <select v-model="sm4.mode" class="ck-select">
                <option>ECB</option><option>CBC</option><option>CFB</option><option>OFB</option><option>CTR</option><option>GCM</option>
              </select>
            </div>
            <div>
              <label class="ck-label">填充方式</label>
              <select v-model="sm4.padding" class="ck-select" :disabled="sm4.mode === 'GCM'">
                <option>PKCS7</option><option>Zero</option><option>NoPadding</option>
              </select>
            </div>
          </div>
        </div>
        <div class="ck-card space-y-3">
          <div>
            <div class="flex justify-between mb-1">
              <label class="ck-label !mb-0 text-amber-400">密钥 (Key / 16-byte Hex)</label>
              <button @click="genSM4Key" class="text-xs text-violet-400">⚡ 随机生成</button>
            </div>
            <input v-model="sm4.key" class="ck-input font-mono ck-trim-space text-xs" placeholder="输入 32 位 Hex..." />
            <div v-if="sm4KeyHint" :class="['mt-1 text-xs', hintClass(sm4KeyHint)]">{{ sm4KeyHint }}</div>
            <div v-if="sm4.key" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (sm4.key.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div v-if="sm4.mode !== 'ECB' && sm4.mode !== 'GCM'">
            <div class="flex justify-between mb-1">
              <label class="ck-label !mb-0 text-cyan-400">初始化向量 (IV / 16-byte Hex)</label>
              <button @click="genSM4IV" class="text-xs text-violet-400">⚡ 随机生成</button>
            </div>
            <input v-model="sm4.iv" class="ck-input font-mono ck-trim-space text-xs" placeholder="输入 32 位 Hex..." />
            <div v-if="sm4IVHint" :class="['mt-1 text-xs', hintClass(sm4IVHint)]">{{ sm4IVHint }}</div>
          </div>
          <div v-if="sm4.mode === 'GCM'" class="space-y-3">
            <div>
              <div class="flex justify-between mb-1">
                <label class="ck-label !mb-0 text-cyan-400">Nonce (12-byte Hex)</label>
                <button @click="genSM4Nonce" class="text-xs text-violet-400">⚡ 随机生成</button>
              </div>
              <input v-model="sm4.nonce" class="ck-input font-mono ck-trim-space text-xs" />
              <div v-if="sm4NonceHint" :class="['mt-1 text-xs', hintClass(sm4NonceHint)]">{{ sm4NonceHint }}</div>
            </div>
            <div>
              <label class="ck-label">附加认证数据 (AAD / 可选 Hex)</label>
              <input v-model="sm4.aad" class="ck-input font-mono ck-trim-space text-xs" />
              <div v-if="sm4AADHint" :class="['mt-1 text-xs', hintClass(sm4AADHint)]">{{ sm4AADHint }}</div>
            </div>
          </div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="sm4.data" label="数据 (Hex)" type="textarea" :rows="4" clearable />
          <div v-if="sm4LenHint" :class="['mt-1 text-xs', hintClass(sm4LenHint)]">{{ sm4LenHint }}</div>
        </div>
      </div>
      <div class="space-y-3 flex flex-col min-h-0 overflow-hidden h-full ck-right-panel">
        <div class="grid grid-cols-2 gap-2 shrink-0">
          <button @click="doSM4Encrypt" class="ck-btn-primary justify-center" :disabled="sm4Disabled"><LockIcon class="w-3.5 h-3.5" />SM4 加密</button>
          <button @click="doSM4Decrypt" class="ck-btn-secondary justify-center" :disabled="sm4Disabled"><UnlockIcon class="w-3.5 h-3.5" />SM4 解密</button>
        </div>
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="sm4Result.data" label="运算结果 (Hex)" type="result" :success="sm4Result.success" copyable />
          <div v-if="sm4Result.extra" class="mt-2 space-y-1">
            <div class="flex justify-between items-center text-[10px]">
              <span class="text-amber-400">使用的 IV / Nonce (Hex):</span>
              <button @click="copy(sm4Result.extra)" class="text-violet-400 hover:text-violet-300">复制</button>
            </div>
            <div class="ck-result !min-h-0 py-1.5 text-[10px] text-amber-300 font-mono break-all">{{ sm4Result.extra }}</div>
          </div>
          <div v-if="sm4Result.error" class="mt-2 text-xs text-red-400">{{ sm4Result.error }}</div>
        </div>
        <div class="ck-card flex-1 overflow-y-auto">
          <p class="ck-section-title">算法原理 & 模式说明 (SM4)</p>
          <div class="text-[11px] space-y-3 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-3 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-violet-400">设计规范</p>
              <p>• 标准: GM/T 0002-2012 / GB/T 32907-2016</p>
              <p>• 结构: 非平衡 Feistel 网络，迭代 32 轮。</p>
              <p>• 参数: 分组长度 128 位，密钥长度 128 位。</p>
              <p>• 输入长度: Hex 需偶数位；NoPadding 时需 16 字节倍数。</p>
            </div>
            <div class="p-3 rounded-lg border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-emerald-400">当前工作模式 ({{ sm4.mode }})</p>
              <p v-for="(line, i) in sm4ModeDesc" :key="i">{{ line }}</p>
            </div>
            <div class="p-3 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-blue-400">应用场景</p>
              <p>• ECB: 仅适合随机小块数据，例如密钥封装中的中间数据。</p>
              <p>• CBC/CFB/OFB/CTR: 常用于文件加密、通道加密等通用场景。</p>
              <p>• GCM: 需要同时保证机密性与完整性的协议，如 VPN、API 调用等。</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- SM9 -->
    <div v-if="activeTab === 'sm9'" class="grid grid-cols-2 gap-4 animate-fade-in h-full overflow-hidden">
      <div class="space-y-3 overflow-y-auto pr-1">
        <div class="ck-card">
          <p class="ck-section-title">SM9 标识密码 (IBC)</p>
          <p class="text-[11px] mb-3" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            无需证书，以用户标识(如邮件/手机号)作为公钥。
          </p>
          <div class="space-y-2">
            <button @click="genSM9MasterKey" class="ck-btn-primary w-full justify-center">
              <KeyIcon class="w-3.5 h-3.5" /> 生成 SM9 主密钥
            </button>
            <div v-if="sm9Master.publicKey" class="ck-card !bg-transparent space-y-2 animate-in fade-in duration-300">
              <div>
                <label class="ck-label text-amber-400">主私钥 (Hex)</label>
                <div class="ck-result ck-key-hex !min-h-0 text-amber-300 text-[10px] break-all max-h-20 overflow-y-auto font-mono">{{ sm9Master.privateKey }}</div>
                <div class="flex gap-3 mt-1">
                  <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                    {{ (sm9Master.privateKey.replace(/\s+/g, '').length / 2) + ' bytes' }}
                  </span>
                </div>
              </div>
              <div>
                <label class="ck-label text-cyan-400">主公钥 (Hex)</label>
                <div class="ck-result ck-key-hex !min-h-0 text-cyan-300 text-[10px] break-all max-h-20 overflow-y-auto font-mono">{{ sm9Master.publicKey }}</div>
                <div class="flex gap-3 mt-1">
                  <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-cyan-400 border-cyan-500/20 bg-cyan-500/5">
                    {{ (sm9Master.publicKey.replace(/\s+/g, '').length / 2) + ' bytes' }}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div class="ck-card space-y-3">
          <div>
            <label class="ck-label">用户标识 (UID / 标识即公钥)</label>
            <input v-model="sm9.uid" class="ck-input" placeholder="例如: alice@cryptokit.com" />
          </div>
          <CryptoPanel v-model="sm9.data" label="待处理数据 (Hex)" type="textarea" :rows="3" clearable />
          <div class="flex gap-2">
            <button @click="doSM9Encrypt" class="ck-btn-primary flex-1 justify-center"><LockIcon class="w-3.5 h-3.5" />标识加密</button>
            <button @click="doSM9Sign" class="ck-btn-secondary flex-1 justify-center"><PenIcon class="w-3.5 h-3.5" />标识签名</button>
          </div>
        </div>
      </div>
      <div class="space-y-3 flex flex-col min-h-0 overflow-hidden h-full ck-right-panel">
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="sm9Result.data" label="运算结果" type="result" :success="sm9Result.success" copyable />
          <div v-if="sm9Result.error" class="mt-2 text-xs text-red-400">{{ sm9Result.error }}</div>
        </div>
        <div class="ck-card flex-1 overflow-y-auto">
          <p class="ck-section-title">算法原理 & 特性 (SM9)</p>
          <div class="text-[11px] space-y-3 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-3 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-violet-400">设计规范</p>
              <p>• 标准: GM/T 0044-2016</p>
              <p>• 技术基础: 基于椭圆曲线上的双线性对 (Pairing) 技术。</p>
            </div>
            <div class="p-3 rounded-lg border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-emerald-400">IBC 优势</p>
              <p>• 标识即公钥: 用户的姓名、邮件等直接作为公钥，无需繁琐的证书申请和在线查询。</p>
              <p>• 简化管理: 极大地简化了密钥管理和分发，适用于移动互联网和物联网。</p>
            </div>
            <div class="p-3 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-blue-400">功能支持</p>
              <p>• 支持数字签名、密钥封装、加密、密钥交换等多种密码服务。</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ZUC -->
    <div v-if="activeTab === 'zuc'" class="grid grid-cols-2 gap-4 animate-fade-in h-full overflow-hidden">
      <div class="space-y-3 overflow-y-auto pr-1">
        <div class="ck-card">
          <p class="ck-section-title">ZUC (祖冲之) 流密码</p>
          <div class="grid grid-cols-2 gap-3 mb-3">
            <div>
              <label class="ck-label">算法版本</label>
              <select v-model="zuc.type" class="ck-select">
                <option value="ZUC-128">ZUC-128 (4G/LTE)</option>
                <option value="ZUC-256">ZUC-256 (5G 增强)</option>
              </select>
            </div>
            <div>
              <label class="ck-label">操作</label>
              <div class="ck-result !min-h-0 py-1.5 text-center text-[10px] text-violet-400 border-violet-500/20 bg-violet-500/5">加解密同向</div>
            </div>
          </div>
          <div class="space-y-3">
            <div>
              <div class="flex justify-between mb-1">
                <label class="ck-label !mb-0 text-amber-400">密钥 (Key / Hex)</label>
                <button @click="genZUCKey" class="text-xs text-violet-400">⚡ 生成</button>
              </div>
              <input v-model="zuc.key" class="ck-input font-mono ck-trim-space text-xs" :placeholder="zuc.type === 'ZUC-256' ? '64位 Hex (32字节)' : '32位 Hex (16字节)'" />
              <div v-if="zuc.key" class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                  {{ (zuc.key.replace(/\s+/g, '').length / 2) + ' bytes' }}
                </span>
              </div>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="ck-label !mb-0 text-cyan-400">向量 (IV / Hex)</label>
                <button @click="genZUCIV" class="text-xs text-violet-400">⚡ 生成</button>
              </div>
              <input v-model="zuc.iv" class="ck-input font-mono ck-trim-space text-xs" :placeholder="zuc.type === 'ZUC-256' ? '50位 Hex (25字节)' : '32位 Hex (16字节)'" />
              <div v-if="zuc.iv" class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-cyan-400 border-cyan-500/20 bg-cyan-500/5">
                  {{ (zuc.iv.replace(/\s+/g, '').length / 2) + ' bytes' }}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="zuc.data" label="待加/解密数据 (Hex)" type="textarea" :rows="4" clearable />
        </div>
        <button @click="doZUCEncrypt" class="ck-btn-primary w-full justify-center">
          <ZapIcon class="w-3.5 h-3.5" /> 执行 ZUC 变换
        </button>
      </div>
      <div class="space-y-3 flex flex-col min-h-0 overflow-hidden h-full ck-right-panel">
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="zucResult.data" label="变换结果 (Hex)" type="result" :success="zucResult.success" copyable />
          <div v-if="zucResult.error" class="mt-2 text-xs text-red-400">{{ zucResult.error }}</div>
        </div>
        <div class="ck-card flex-1 overflow-y-auto">
          <p class="ck-section-title">算法原理 & 特性 (ZUC)</p>
          <div class="text-[11px] space-y-3 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-3 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-violet-400">设计背景</p>
              <p>• 标准: GM/T 0001-2012</p>
              <p>• 国际标准: 3GPP 4G LTE 核心加密算法之一。</p>
            </div>
            <div class="p-3 rounded-lg border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-emerald-400">算法结构</p>
              <p>• 核心组成: 线性反馈移位寄存器 (LFSR)、比特重组 (BR) 和非线性函数 F。</p>
              <p>• 效率: 极高的软件和硬件执行效率。</p>
            </div>
            <div class="p-3 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-blue-400">新版本 ZUC-256</p>
              <p>• 为满足 512G 等更高安全需求，2024年正式发布 ZUC-256 标准，提供 256 位安全强度。</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Digital Envelope (GM/T 0010-2012) -->
    <div v-if="activeTab === 'envelope'" class="grid grid-cols-2 gap-4 animate-fade-in h-full overflow-hidden">
      <div class="space-y-3 overflow-y-auto pr-1">
        <div class="ck-card space-y-4">
          <p class="ck-section-title">制作数字信封 (密封)</p>
          <div class="space-y-3">
            <div>
              <label class="ck-label text-amber-400">发送方 SM2 私钥 (PEM/Hex) - 用于签名</label>
              <textarea v-model="envelope.senderPriv" class="ck-textarea text-[10px] font-mono" rows="3" placeholder="粘贴 SM2 私钥..."></textarea>
            </div>
            <div>
              <label class="ck-label text-cyan-400">接收方 SM2 公钥 (PEM/Hex) - 用于加密</label>
              <textarea v-model="envelope.receiverPub" class="ck-textarea text-[10px] font-mono" rows="3" placeholder="粘贴 SM2 公钥..."></textarea>
            </div>
            <CryptoPanel v-model="envelope.data" label="待密封原始数据 (Hex)" type="textarea" :rows="3" clearable />
            <button @click="makeEnvelope" class="ck-btn-primary w-full justify-center">
              <PackageIcon class="w-3.5 h-3.5" /> 制作并导出信封
            </button>
          </div>
        </div>

        <div class="ck-card space-y-4">
          <p class="ck-section-title">拆解数字信封 (开封)</p>
          <div class="space-y-3">
            <div>
              <label class="ck-label text-amber-400">接收方 SM2 私钥 (PEM/Hex) - 用于解密</label>
              <textarea v-model="envelope.receiverPriv" class="ck-textarea text-[10px] font-mono" rows="3" placeholder="粘贴 SM2 私钥..."></textarea>
            </div>
            <div>
              <label class="ck-label text-cyan-400">发送方 SM2 公钥 (PEM/Hex) - 用于验签</label>
              <textarea v-model="envelope.senderPub" class="ck-textarea text-[10px] font-mono" rows="3" placeholder="粘贴 SM2 公钥..."></textarea>
            </div>
            <CryptoPanel v-model="envelope.envelopeData" label="待拆解信封数据 (Hex)" type="textarea" :rows="3" clearable />
            <button @click="openEnvelope" class="ck-btn-secondary w-full justify-center">
              <PackageOpenIcon class="w-3.5 h-3.5" /> 拆解并验证数据
            </button>
          </div>
        </div>
      </div>

      <div class="space-y-3 flex flex-col min-h-0 overflow-hidden h-full">
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="envelopeResult.data" label="处理结果" type="result" :success="envelopeResult.success" copyable />
          <div v-if="envelopeResult.error" class="mt-2 text-xs text-red-400">{{ envelopeResult.error }}</div>
        </div>
        
        <div class="ck-card flex-1 overflow-y-auto">
          <p class="ck-section-title">算法原理 (GM/T 0010-2012)</p>
          <div class="text-[11px] space-y-3 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-3 rounded-lg border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-violet-400">密封流程 (Seal)</p>
              <p>1. <span class="text-violet-300">签名</span>: 发送者用私钥对原文签名。</p>
              <p>2. <span class="text-violet-300">加密数据</span>: 随机生成 SM4 密钥，对 (原文+签名) 进行加密。</p>
              <p>3. <span class="text-violet-300">加密密钥</span>: 使用接收者 SM2 公钥加密 SM4 密钥。</p>
              <p>4. <span class="text-violet-300">打包</span>: 按照标准封装所有信息。</p>
            </div>
            <div class="p-3 rounded-lg border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-emerald-400">拆封流程 (Open)</p>
              <p>1. <span class="text-emerald-300">解密密钥</span>: 接收者用私钥解出 SM4 密钥。</p>
              <p>2. <span class="text-emerald-300">解密数据</span>: 用 SM4 密钥解出 (原文+签名)。</p>
              <p>3. <span class="text-emerald-300">验签</span>: 用发送者公钥验证签名，确保来源可靠且未被篡改。</p>
            </div>
            <div class="p-3 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-1 text-blue-400">组合优势</p>
              <p>• 结合了对称加密的效率与非对称加密的安全性，是实现大规模数据机密传输的最佳实践。</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, watch, computed } from 'vue'
import { storeToRefs } from 'pinia'
import { FlagIcon, KeyIcon, LockIcon, UnlockIcon, PenIcon, CheckCircleIcon, CopyIcon, HashIcon, ZapIcon, ShieldCheckIcon, InfoIcon, XIcon, PackageIcon, PackageOpenIcon } from 'lucide-vue-next'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import { SM2GenerateKey, SM2Encrypt, SM2Decrypt, SM2Sign, SM2Verify, SM3Hash, SM3HMAC, SM4Encrypt, SM4Decrypt, SM9GenerateMasterKey, SM9Sign, SM9Encrypt, ZUCEncrypt, MakeGMEnvelope, OpenGMEnvelope } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'sm2', label: 'SM2' },
  { id: 'sm3', label: 'SM3' },
  { id: 'sm4', label: 'SM4' },
  { id: 'sm9', label: 'SM9 (IBC)' },
  { id: 'zuc', label: 'ZUC (祖冲之)' },
  { id: 'envelope', label: '数字信封' },
]
const activeTab = ref('sm2')

// Principles modal / info
const showPrinciple = ref(false)
const principles = {
  sm2: {
    title: 'SM2 算法原理',
    content: 'SM2 是国家密码管理局发布的椭圆曲线公钥密码算法。安全性基于椭圆曲线离散对数难题。\n- 曲线参数：sm2p256v1 (256位)\n- 功能：包括数字签名、公钥加密、密钥交换。\n- 特点：在相同安全强度下，密钥长度远小于 RSA，计算速度更快。'
  },
  sm3: {
    title: 'SM3 算法原理',
    content: 'SM3 是国家密码管理局发布的杂凑(Hash)算法。输出长度为 256 位。\n- 设计特性：采用 Merkle-Damgård 结构，安全性与 SHA-256 相当。\n- 应用：数字签名、消息认证码(HMAC)、伪随机数生成等。'
  },
  sm4: {
    title: 'SM4 算法原理',
    content: 'SM4 是国家密码管理局发布的分组对称加密算法。分组长度和密钥长度均为 128 位。\n- 结构：采用非平衡 Feistel 网络结构。\n- 模式：支持 ECB, CBC, CFB, OFB, CTR, GCM 等主流工作模式。'
  },
  sm9: {
    title: 'SM9 算法原理',
    content: 'SM9 是标识密码算法(IBC)。无需颁发数字证书，直接以用户标识(如邮件、手机号)作为公钥。\n- 技术基础：基于双线性对(Pairing)技术。\n- 优势：简化了密钥管理和分发流程，适用于物联网、大规模用户环境。'
  },
  zuc: {
    title: 'ZUC (祖冲之) 算法原理',
    content: 'ZUC 是一种流密码算法。由中国自主设计，已成为 4G/5G 移动通信国际标准。\n- 结构：由线性反馈移位寄存器(LFSR)、比特重组和非线性函数 F 组成。\n- 版本：ZUC-128 (128位密钥) 和 ZUC-256 (256位密钥)。'
  },
  envelope: {
    title: '数字信封原理 (GM/T 0010)',
    content: '数字信封结合了非对称加密和对称加密的优点。\n1. 签名：发送方用私钥签名，保证不可抵赖性。\n2. 加密：随机生成对称密钥(SM4)加密大容量数据。\n3. 封装：用接收方公钥加密对称密钥。\n解开时流程相反，确保了数据的机密性、完整性和身份真实性。'
  }
}

const currentPrinciple = computed(() => principles[activeTab.value])

// SM2
const sm2Subtabs = [
  { id: 'keygen', label: '密钥生成' },
  { id: 'enc', label: '加密/解密' },
  { id: 'sign', label: '签名/验签' },
]
const sm2Sub = ref('keygen')
const sm2KeyFormat = ref('hex')
const sm2Keys = reactive({ privateKey: '', publicKey: '', privHex: '', pubHex: '' })
const sm2Enc = reactive({ publicKey: '', privateKey: '', data: '' })
const sm2EncResult = reactive({ data: '', error: '', success: null })
const sm2Sign = reactive({ privateKey: '', publicKey: '', id: '', data: '' })
const sm2SignResult = reactive({ data: '', error: '', success: null })
const sm2Signature = ref('') // 单独保存签名 Hex，避免被验签结果覆盖

async function genSM2Key() {
  const r = await SM2GenerateKey()
  if (r.success) { 
    sm2Keys.privateKey = r.privateKey
    sm2Keys.publicKey = r.publicKey 
    sm2Keys.privHex = r.privHex || ''
    sm2Keys.pubHex = r.pubHex || ''

    // Auto-sync to other sub-tabs with correct format
    if (sm2KeyFormat.value === 'hex') {
      sm2Enc.publicKey = r.pubHex
      sm2Enc.privateKey = r.privHex
      sm2Sign.publicKey = r.pubHex
      sm2Sign.privateKey = r.privHex
    } else {
      sm2Enc.publicKey = r.publicKey
      sm2Enc.privateKey = r.privateKey
      sm2Sign.publicKey = r.publicKey
      sm2Sign.privateKey = r.privateKey
    }
  }
}

// Format watcher for auto-sync
watch(sm2KeyFormat, (newFormat) => {
  if (!sm2Keys.privateKey) return
  if (newFormat === 'hex') {
    sm2Enc.publicKey = sm2Keys.pubHex
    sm2Enc.privateKey = sm2Keys.privHex
    sm2Sign.publicKey = sm2Keys.pubHex
    sm2Sign.privateKey = sm2Keys.privHex
  } else {
    sm2Enc.publicKey = sm2Keys.publicKey
    sm2Enc.privateKey = sm2Keys.privateKey
    sm2Sign.publicKey = sm2Keys.publicKey
    sm2Sign.privateKey = sm2Keys.privateKey
  }
})

async function sm2Encrypt() {
  const r = await SM2Encrypt({ key: sm2Enc.publicKey, data: sm2Enc.data, mode: 'C1C3C2' })
  sm2EncResult.data = r.data; sm2EncResult.error = r.error; sm2EncResult.success = r.success
}
async function sm2Decrypt() {
  const r = await SM2Decrypt({ key: sm2Enc.privateKey, data: sm2Enc.data, mode: 'C1C3C2' })
  sm2EncResult.data = r.data; sm2EncResult.error = r.error; sm2EncResult.success = r.success
}
async function doSM2Sign() {
  const r = await SM2Sign({ privateKey: sm2Sign.privateKey, data: sm2Sign.data, id: sm2Sign.id })
  sm2Signature.value = r.data || ''
  sm2SignResult.data = r.data; sm2SignResult.error = r.error; sm2SignResult.success = r.success
}
async function doSM2Verify() {
  const signatureHex = sm2Signature.value || sm2SignResult.data
  const r = await SM2Verify({ publicKey: sm2Sign.publicKey, data: sm2Sign.data, signature: signatureHex, id: sm2Sign.id })
  sm2SignResult.data = r.data; sm2SignResult.error = r.error; sm2SignResult.success = r.success
}

// SM3
const sm3Data = ref('')
const sm3Key = ref('')
const sm3Format = ref('hex')
const sm3Sub = ref('hash')
const sm3Result = reactive({ data: '', error: '', success: null })

function toHex(s) {
  return sm3Format.value === 'hex' ? s : Array.from(new TextEncoder().encode(s)).map(b => b.toString(16).padStart(2,'0')).join('').toUpperCase()
}
async function computeSM3() {
  sm3Sub.value = 'hash'
  const r = await SM3Hash({ data: toHex(sm3Data.value) })
  sm3Result.data = r.data; sm3Result.error = r.error; sm3Result.success = r.success
}
async function computeSM3HMAC() {
  sm3Sub.value = 'hmac'
  const r = await SM3HMAC({ key: sm3Key.value, data: toHex(sm3Data.value) })
  sm3Result.data = r.data; sm3Result.error = r.error; sm3Result.success = r.success
}
function genSM3Key() {
  const b = new Uint8Array(32); crypto.getRandomValues(b)
  sm3Key.value = Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('').toUpperCase()
}

// SM4
const sm4 = reactive({ mode: 'CBC', padding: 'PKCS7', key: '', iv: '', nonce: '', aad: '', data: '' })
const sm4Result = reactive({ data: '', error: '', extra: '', success: null })
const sm4LenHint = computed(() => {
  const clean = (sm4.data || '').replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'Hex 长度必须为偶数位'
  if (sm4.padding === 'NoPadding' && clean.length % 32 !== 0) {
    return 'NoPadding 时长度必须是 16 字节(32位Hex)的倍数'
  }
  return ''
})
const sm4KeyHint = computed(() => {
  const clean = (sm4.key || '').replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) return '密钥 Hex 长度必须为偶数位'
  if (clean.length !== 32) return 'SM4 密钥必须为 16 字节(32位Hex)'
  return ''
})
const sm4IVHint = computed(() => {
  if (sm4.mode === 'ECB' || sm4.mode === 'GCM') return ''
  const clean = (sm4.iv || '').replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'IV Hex 长度必须为偶数位'
  if (clean.length !== 32) return 'IV 必须为 16 字节(32位Hex)'
  return ''
})
const sm4NonceHint = computed(() => {
  if (sm4.mode !== 'GCM') return ''
  const clean = (sm4.nonce || '').replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'Nonce Hex 长度必须为偶数位'
  if (clean.length !== 24) return 'Nonce 必须为 12 字节(24位Hex)'
  return ''
})
const sm4AADHint = computed(() => {
  const clean = (sm4.aad || '').replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) return 'AAD Hex 长度必须为偶数位'
  return ''
})

function hintClass(text) {
  if (!text) return ''
  if (text.includes('必须') || text.includes('需') || text.includes('应为')) return 'text-red-400'
  return 'text-amber-400'
}

const sm4Disabled = computed(() => !sm4.key || !!(sm4KeyHint.value || sm4IVHint.value || sm4NonceHint.value || sm4AADHint.value || sm4LenHint.value))
const sm4ModeDesc = computed(() => {
  switch (sm4.mode) {
    case 'ECB':
      return [
        '电子密码本模式 (Electronic Code Book)。',
        '每个 16 字节分组独立加密，相同明文块得到相同密文块，易泄露模式信息。',
        '仅适合随机化后的小块数据，不推荐直接用于大文件/结构化数据。'
      ]
    case 'CBC':
      return [
        '密码分组链接模式 (Cipher Block Chaining)。',
        '每个明文块先与前一块密文异或，再加密；首块使用随机 IV。',
        '能隐藏明文模式，但加解密均为串行，适合一般数据加密场景。'
      ]
    case 'CFB':
      return [
        '密文反馈模式 (Cipher Feedback)。',
        '将分组密码当作自同步流密码使用，支持非分组长度数据。',
        '适合对实时数据流进行加密，如交互式会话。'
      ]
    case 'OFB':
      return [
        '输出反馈模式 (Output Feedback)。',
        '仅依赖密钥和 IV 生成密钥流，明文/密文错误不会传播。',
        '适合噪声敏感场景，但必须保证 (Key, IV) 组合唯一。'
      ]
    case 'CTR':
      return [
        '计数器模式 (Counter)。',
        '对递增计数器加密生成密钥流，可完全并行处理，性能优异。',
        '常用于高吞吐网络加密与存储加密，同样要求计数器不重用。'
      ]
    case 'GCM':
      return [
        'Galois/Counter Mode，认证加密模式 (AEAD)。',
        '在 CTR 的基础上引入 GF(2¹²⁸) 乘法实现完整性认证，支持附加认证数据 (AAD)。',
        '同时保证机密性与完整性，是现代协议 (如 TLS/QUIC) 的主流模式。'
      ]
    default:
      return []
  }
})

async function doSM4Encrypt() {
  if (sm4.padding === 'NoPadding' && sm4.data.replace(/\s+/g, '').length % 32 !== 0) {
    sm4Result.success = false
    sm4Result.data = ''
    sm4Result.error = '错误：在 NoPadding 模式下，输入数据的长度必须是 16 字节（32 位 Hex）的倍数'
    return
  }
  const r = await SM4Encrypt(sm4)
  sm4Result.data = r.data; sm4Result.error = r.error; sm4Result.extra = r.extra; sm4Result.success = r.success
}
async function doSM4Decrypt() {
  if (sm4.data.replace(/\s+/g, '').length % 32 !== 0) {
    sm4Result.success = false
    sm4Result.data = ''
    sm4Result.error = '错误：SM4 密文长度必须是 16 字节（32 位 Hex）的倍数'
    return
  }
  const r = await SM4Decrypt(sm4)
  sm4Result.data = r.data; sm4Result.error = r.error; sm4Result.extra = r.extra; sm4Result.success = r.success
}
function genSM4Key() { const b = new Uint8Array(16); crypto.getRandomValues(b); sm4.key = Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase() }
function genSM4IV()  { const b = new Uint8Array(16); crypto.getRandomValues(b); sm4.iv  = Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase() }
function genSM4Nonce(){ const b = new Uint8Array(12); crypto.getRandomValues(b); sm4.nonce= Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase() }

// SM9
const sm9Master = reactive({ privateKey: '', publicKey: '' })
const sm9 = reactive({ uid: '', data: '' })
const sm9Result = reactive({ data: '', error: '', success: null })

async function genSM9MasterKey() {
  const r = await SM9GenerateMasterKey()
  if (r.success) { sm9Master.privateKey = r.masterPrivateKey; sm9Master.publicKey = r.masterPublicKey }
}
async function doSM9Encrypt() {
  const r = await SM9Encrypt({ masterPublicKey: sm9Master.publicKey, uid: sm9.uid, data: sm9.data })
  sm9Result.data = r.data; sm9Result.error = r.error; sm9Result.success = r.success
}
async function doSM9Sign() {
  const r = await SM9Sign({ masterPrivateKey: sm9Master.privateKey, uid: sm9.uid, data: sm9.data })
  sm9Result.data = r.data; sm9Result.error = r.error; sm9Result.success = r.success
}

// ZUC
const zuc = reactive({ type: 'ZUC-128', key: '', iv: '', data: '' })
const zucResult = reactive({ data: '', error: '', success: null })

async function doZUCEncrypt() {
  const r = await ZUCEncrypt(zuc)
  zucResult.data = r.data; zucResult.error = r.error; zucResult.success = r.success
}

// Envelope (GM/T 0010-2012)
const envelope = reactive({ senderPriv: '', receiverPub: '', data: '', receiverPriv: '', senderPub: '', envelopeData: '' })
const envelopeResult = reactive({ data: '', error: '', success: null })

async function makeEnvelope() {
  if (!envelope.senderPriv || !envelope.receiverPub || !envelope.data) {
    envelopeResult.error = '请填写完整的发送方私钥、接收方公钥和待处理数据'
    envelopeResult.success = false
    return
  }
  const r = await MakeGMEnvelope({
    senderPriv: envelope.senderPriv,
    receiverPub: envelope.receiverPub,
    data: envelope.data
  })
  envelopeResult.data = r.data; envelopeResult.error = r.error; envelopeResult.success = r.success
}

async function openEnvelope() {
  if (!envelope.receiverPriv || !envelope.senderPub || !envelope.envelopeData) {
    envelopeResult.error = '请填写完整的接收方私钥、发送方公钥和信封数据'
    envelopeResult.success = false
    return
  }
  const r = await OpenGMEnvelope({
    receiverPriv: envelope.receiverPriv,
    senderPub: envelope.senderPub,
    envelopeData: envelope.envelopeData
  })
  envelopeResult.data = r.data; envelopeResult.error = r.error; envelopeResult.success = r.success
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

async function copy(text) {
  if (!text) return
  await navigator.clipboard.writeText(text)
  store.showToast('已复制')
}
</script>
