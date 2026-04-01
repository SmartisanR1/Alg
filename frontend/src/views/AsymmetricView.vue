<template>
  <PageLayout title="非对称算法" subtitle="RSA · SM2 · SM9 · ECDSA · ECDH · Ed25519 · X25519"
              icon-bg="bg-cyan-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <KeyIcon class="w-4 h-4 text-cyan-400" />
    </template>

    <template #extra>
      <button @click="showPrinciple = true" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-violet-500/10 text-violet-400 hover:bg-violet-500/20 transition-all text-xs font-medium border border-violet-500/20">
        <InfoIcon class="w-3.5 h-3.5" /> 算法原理
      </button>
    </template>

    <!-- Principle Modal (HQC Style) -->
    <transition name="fade">
      <div v-if="showPrinciple" class="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" @click.self="showPrinciple = false">
        <div class="ck-card max-w-2xl w-full shadow-2xl animate-in zoom-in-95 duration-200 overflow-hidden flex flex-col max-h-[85vh]" :class="isDark ? 'bg-dark-card border-dark-border' : 'bg-white border-gray-200'">
          <div class="flex justify-between items-center p-4 border-b shrink-0" :class="isDark ? 'border-dark-border' : 'border-gray-100'">
            <h3 class="text-sm font-bold flex items-center gap-2">
              <ShieldCheckIcon class="w-4 h-4 text-violet-400" /> {{ currentPrinciple.title }}
            </h3>
            <button @click="showPrinciple = false" class="p-1 hover:bg-gray-100 dark:hover:bg-dark-hover rounded-md transition-colors">
              <XIcon class="w-4 h-4 text-dark-muted" />
            </button>
          </div>
          <div class="flex-1 overflow-y-auto p-6 custom-scrollbar">
            <div class="space-y-5">
              <div v-for="(section, idx) in parsedPrinciples" :key="idx" 
                   class="p-4 rounded-xl border transition-all hover:shadow-md"
                   :class="[
                     idx % 3 === 0 ? (isDark ? 'bg-violet-500/5 border-violet-500/10' : 'bg-violet-50 border-violet-100') :
                     idx % 3 === 1 ? (isDark ? 'bg-emerald-500/5 border-emerald-500/10' : 'bg-emerald-50 border-emerald-100') :
                     (isDark ? 'bg-blue-500/5 border-blue-500/10' : 'bg-blue-50 border-blue-100')
                   ]">
                <p class="font-bold mb-2.5 text-sm flex items-center gap-2"
                   :class="[
                     idx % 3 === 0 ? 'text-violet-400' :
                     idx % 3 === 1 ? 'text-emerald-400' :
                     'text-blue-400'
                   ]">
                  <span class="w-1.5 h-1.5 rounded-full" :class="idx % 3 === 0 ? 'bg-violet-400' : idx % 3 === 1 ? 'bg-emerald-400' : 'bg-blue-400'"></span>
                  {{ section.title }}
                </p>
                <div class="text-xs leading-relaxed space-y-2 opacity-90" :class="isDark ? 'text-dark-muted' : 'text-gray-600'">
                  <p v-for="(line, lIdx) in section.content" :key="lIdx" class="flex items-start gap-2">
                    <span v-if="line.startsWith('•')" class="mt-1.5 w-1 h-1 rounded-full bg-current shrink-0 opacity-40"></span>
                    <span>{{ line.startsWith('•') ? line.substring(1).trim() : line }}</span>
                  </p>
                </div>
              </div>
            </div>
          </div>
          <div class="p-4 border-t shrink-0 flex justify-end bg-gray-50/50 dark:bg-dark-bg/20" :class="isDark ? 'border-dark-border' : 'border-gray-100'">
            <button @click="showPrinciple = false" class="ck-btn-primary px-8 py-2 shadow-lg shadow-violet-500/20">确认并返回</button>
          </div>
        </div>
      </div>
    </transition>

    <!-- RSA -->
    <div v-if="activeTab === 'rsa'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card">
          <p class="ck-section-title">RSA 密钥生成</p>
          <div class="flex gap-2 mb-4">
            <select v-model="rsa.bits" class="ck-select flex-1">
              <option :value="1024">1024 bit</option>
              <option :value="2048">2048 bit</option>
              <option :value="3072">3072 bit</option>
              <option :value="4096">4096 bit</option>
            </select>
            <select v-model="asymKeyFormat" class="ck-select flex-1">
              <option value="pem">PEM 格式</option>
              <option value="hex">HEX 格式</option>
            </select>
            <button @click="genRSAKey" class="ck-btn-primary flex-1 justify-center">
              <KeyIcon class="w-3.5 h-3.5" /> 生成密钥
            </button>
          </div>
          <div v-if="rsaKeys.privateKey" class="space-y-3 animate-in fade-in duration-300">
            <div>
              <div class="flex justify-between mb-1">
                <label class="ck-label !mb-0 text-amber-400">私钥 ({{ asymKeyFormat.toUpperCase() }})</label>
                <button @click="copy(asymKeyFormat === 'pem' ? rsaKeys.privateKey : rsaKeys.privHex)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="ck-result ck-key-hex !min-h-0 text-amber-300 !text-[10px] break-all max-h-32 overflow-y-auto font-mono">
                {{ asymKeyFormat === 'pem' ? rsaKeys.privateKey : rsaKeys.privHex }}
              </div>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="ck-label !mb-0 text-cyan-400">公钥 ({{ asymKeyFormat.toUpperCase() }})</label>
                <button @click="copy(asymKeyFormat === 'pem' ? rsaKeys.publicKey : rsaKeys.pubHex)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="ck-result ck-key-hex !min-h-0 text-cyan-300 !text-[10px] break-all max-h-24 overflow-y-auto font-mono">
                {{ asymKeyFormat === 'pem' ? rsaKeys.publicKey : rsaKeys.pubHex }}
              </div>
            </div>
          </div>
        </div>
        <div class="ck-card space-y-2">
          <div class="grid grid-cols-2 gap-3 mb-2">
            <div>
              <label class="ck-label">填充模式 (Padding)</label>
              <select v-model="rsa.padding" class="ck-select">
                <option value="PKCS1v15">PKCS#1 v1.5</option>
                <option value="OAEP">OAEP (加密推荐)</option>
                <option value="PSS">PSS (签名推荐)</option>
              </select>
            </div>
            <div>
              <label class="ck-label">Hash 算法</label>
              <select v-model="rsa.hash" class="ck-select">
                <option value="SHA256">SHA-256</option>
                <option value="SHA384">SHA-384</option>
                <option value="SHA512">SHA-512</option>
                <option value="SHA1">SHA-1 (旧标准)</option>
              </select>
            </div>
          </div>
          <div>
            <label class="ck-label">密钥内容 (PEM/Hex)</label>
            <textarea v-model="rsa.key" class="ck-textarea text-[10px] font-mono" rows="3" placeholder="粘贴公钥(加密/验签)或私钥(解密/签名)..." />
          </div>
          <CryptoPanel v-model="rsa.data" label="待处理数据 (Hex)" type="textarea" :rows="3" clearable />
        </div>
      </div>
      <div class="ck-stack ck-right-panel">
        <div class="grid grid-cols-2 gap-2">
          <button @click="rsaEncrypt" class="ck-btn-primary justify-center"><LockIcon class="w-3.5 h-3.5"/>加密</button>
          <button @click="rsaDecrypt" class="ck-btn-secondary justify-center"><UnlockIcon class="w-3.5 h-3.5"/>解密</button>
          <button @click="rsaSign" class="ck-btn-success justify-center"><PenIcon class="w-3.5 h-3.5"/>签名</button>
          <button @click="rsaVerify" class="ck-btn-secondary justify-center"><CheckCircleIcon class="w-3.5 h-3.5"/>验签</button>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="rsaResult.data" label="运算结果" type="result" :success="rsaResult.success" copyable />
          <div v-if="rsaResult.error" class="mt-2 text-xs text-red-400">{{ rsaResult.error }}</div>
        </div>
      </div>
    </div>

    <!-- SM2 -->
    <div v-if="activeTab === 'sm2'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="flex gap-1 p-1 rounded-xl w-fit shrink-0 mb-1" :class="isDark ? 'bg-dark-card border border-dark-border' : 'bg-light-card border border-light-border'">
          <button v-for="s in sm2Subtabs" :key="s.id"
                  class="px-4 py-1.5 rounded-lg text-xs font-bold transition-all"
                  :class="sm2Sub === s.id ? (isDark ? 'bg-dark-accent text-white shadow-lg shadow-dark-accent/20' : 'bg-light-accent text-white shadow-md shadow-light-accent/20') : (isDark ? 'text-dark-muted hover:text-dark-text' : 'text-light-muted hover:text-light-text')"
                  @click="sm2Sub = s.id">
            {{ s.label }}
          </button>
        </div>

        <div v-if="sm2Sub === 'keygen'" class="ck-card flex flex-col flex-1 min-h-0 animate-in slide-in-from-left-2 duration-300">
          <p class="ck-section-title">SM2 密钥对生成</p>
          <div class="flex gap-2 mb-4">
            <select v-model="asymKeyFormat" class="ck-select flex-1">
              <option value="pem">PEM 格式 (X.509/PKCS#8)</option>
              <option value="hex">HEX 格式 (Raw Uncompressed)</option>
            </select>
            <button @click="genSM2Key" class="ck-btn-primary px-6">
              <KeyIcon class="w-3.5 h-3.5" /> 生成密钥对
            </button>
          </div>
          <div v-if="sm2Keys.privateKey" class="space-y-4 flex-1 overflow-y-auto pr-1 custom-scrollbar">
            <div>
              <div class="flex justify-between mb-1.5">
                <label class="ck-label !mb-0 text-amber-400">私钥 ({{ asymKeyFormat.toUpperCase() }})</label>
                <div class="flex gap-2">
                  <button @click="copy(asymKeyFormat === 'pem' ? sm2Keys.privateKey : sm2Keys.privHex)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /> 复制</button>
                </div>
              </div>
              <div class="ck-result ck-key-hex !min-h-[80px] text-amber-300 !text-[11px] break-all max-h-40 overflow-y-auto font-mono border-amber-500/10 bg-amber-500/5">
                {{ asymKeyFormat === 'pem' ? sm2Keys.privateKey : sm2Keys.privHex }}
              </div>
            </div>
            <div>
              <div class="flex justify-between mb-1.5">
                <label class="ck-label !mb-0 text-cyan-400">公钥 ({{ asymKeyFormat.toUpperCase() }})</label>
                <button @click="copy(asymKeyFormat === 'pem' ? sm2Keys.publicKey : sm2Keys.pubHex)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /> 复制</button>
              </div>
              <div class="ck-result ck-key-hex !min-h-[60px] text-cyan-300 !text-[11px] break-all max-h-32 overflow-y-auto font-mono border-cyan-500/10 bg-cyan-500/5">
                {{ asymKeyFormat === 'pem' ? sm2Keys.publicKey : sm2Keys.pubHex }}
              </div>
            </div>
          </div>
          <div v-else class="flex-1 flex flex-col items-center justify-center text-dark-muted opacity-40 border-2 border-dashed border-dark-border rounded-xl mt-2">
            <KeyIcon class="w-10 h-10 mb-2" />
            <p class="text-xs">点击上方按钮生成符合国密标准的 SM2 密钥对</p>
          </div>
        </div>

        <div v-if="sm2Sub === 'enc'" class="flex flex-col flex-1 min-h-0 space-y-3 animate-in slide-in-from-left-2 duration-300">
          <div class="ck-card space-y-3">
            <p class="ck-section-title">SM2 加密/解密配置</p>
            <div class="grid grid-cols-1 gap-3">
              <CryptoPanel v-model="sm2Enc.publicKey" label="公钥 (PEM/Hex) — 用于加密" type="textarea" :rows="asymKeyFormat === 'hex' ? 2 : 3" clearable />
              <CryptoPanel v-model="sm2Enc.privateKey" label="私钥 (PEM/Hex) — 用于解密" type="textarea" :rows="asymKeyFormat === 'hex' ? 2 : 3" clearable />
            </div>
          </div>
          <div class="ck-card shrink-0">
            <CryptoPanel v-model="sm2Enc.data" label="数据 (Hex)" type="textarea" :rows="2" clearable />
          </div>
          <div class="flex gap-2 shrink-0">
            <button @click="sm2Encrypt" class="ck-btn-primary flex-1 justify-center py-2"><LockIcon class="w-3.5 h-3.5" /> 加密</button>
            <button @click="sm2Decrypt" class="ck-btn-secondary flex-1 justify-center py-2"><UnlockIcon class="w-3.5 h-3.5" /> 解密</button>
          </div>
        </div>

        <div v-if="sm2Sub === 'sign'" class="flex flex-col flex-1 min-h-0 space-y-3 animate-in slide-in-from-left-2 duration-300">
          <div class="ck-card space-y-3">
            <p class="ck-section-title">SM2 签名/验签配置</p>
            <div class="grid grid-cols-1 gap-3">
              <CryptoPanel v-model="sm2Sign.privateKey" label="私钥 (PEM/Hex) — 用于签名" type="textarea" :rows="asymKeyFormat === 'hex' ? 2 : 3" clearable />
              <CryptoPanel v-model="sm2Sign.publicKey" label="公钥 (PEM/Hex) — 用于验签" type="textarea" :rows="asymKeyFormat === 'hex' ? 2 : 3" clearable />
              <div>
                <label class="ck-label">用户标识 (IDA / 可选)</label>
                <input v-model="sm2Sign.id" placeholder="默认: 1234567812345678" class="ck-input font-mono text-xs" />
              </div>
            </div>
          </div>
          <div class="ck-card shrink-0">
            <CryptoPanel v-model="sm2Sign.data" label="待处理数据 (Hex)" type="textarea" :rows="2" clearable />
          </div>
          <div class="flex gap-2 shrink-0">
            <button @click="doSM2Sign" class="ck-btn-primary flex-1 justify-center py-2"><PenIcon class="w-3.5 h-3.5" /> 签名</button>
            <button @click="doSM2Verify" class="ck-btn-secondary flex-1 justify-center py-2"><CheckCircleIcon class="w-3.5 h-3.5" /> 验签</button>
          </div>
        </div>
      </div>

      <div class="ck-stack ck-right-panel">
        <div class="ck-card h-full flex flex-col">
          <p class="ck-section-title">运算结果</p>
          <div class="flex-1 flex flex-col min-h-0">
            <div class="flex-1 overflow-y-auto">
              <div v-if="sm2Result.data || sm2Result.error" class="animate-in fade-in duration-300">
                <div class="flex justify-between items-center mb-1.5">
                  <span class="text-[10px] font-bold" :class="sm2Result.success ? 'text-emerald-400' : 'text-red-400'">
                    {{ sm2Result.success ? '执行成功' : '执行失败' }}
                  </span>
                  <button v-if="sm2Result.data" @click="copy(sm2Result.data)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /> 复制</button>
                </div>
                <div class="ck-result !min-h-[120px] !max-h-none font-mono text-[11px] break-all leading-relaxed" 
                     :class="[isDark ? 'bg-dark-bg/50' : 'bg-gray-50', sm2Result.error ? 'text-red-400 border-red-500/20' : 'text-emerald-400 border-emerald-500/20']">
                  {{ sm2Result.error || sm2Result.data }}
                </div>
              </div>
              <div v-else class="h-full flex flex-col items-center justify-center text-dark-muted opacity-30 italic py-20">
                <div class="w-12 h-12 rounded-full border-2 border-dashed border-dark-border flex items-center justify-center mb-3">
                  <ZapIcon class="w-6 h-6" />
                </div>
                <p class="text-xs">等待运算结果...</p>
              </div>
            </div>
          </div>
        </div>
        
      </div>
    </div>

    <!-- SM9 -->
    <div v-if="activeTab === 'sm9'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card">
          <p class="ck-section-title">SM9 标识密码 (IBC)</p>
          <div class="space-y-2">
            <button @click="genSM9MasterKey" class="ck-btn-primary w-full justify-center">
              <KeyIcon class="w-3.5 h-3.5" /> 生成 SM9 主密钥
            </button>
            <div v-if="sm9Master.publicKey" class="ck-card !bg-transparent space-y-2 animate-in fade-in duration-300">
              <div>
                <label class="ck-label text-amber-400">主私钥 (Hex)</label>
                <div class="ck-result ck-key-hex !min-h-0 text-amber-300 text-[10px] break-all max-h-20 overflow-y-auto font-mono">{{ sm9Master.privateKey }}</div>
              </div>
              <div>
                <label class="ck-label text-cyan-400">主公钥 (Hex)</label>
                <div class="ck-result ck-key-hex !min-h-0 text-cyan-300 text-[10px] break-all max-h-20 overflow-y-auto font-mono">{{ sm9Master.publicKey }}</div>
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
      <div class="ck-stack ck-right-panel">
        <div class="ck-card">
          <CryptoPanel v-model="sm9Result.data" label="运算结果" type="result" :success="sm9Result.success" copyable />
          <div v-if="sm9Result.error" class="mt-2 text-xs text-red-400">{{ sm9Result.error }}</div>
        </div>
      </div>
    </div>

    <!-- ECC -->
    <div v-if="activeTab === 'ecc'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card">
          <p class="ck-section-title">ECC 曲线密钥生成</p>
          <div class="flex gap-2 mb-4">
            <select v-model="ecc.curve" class="ck-select flex-1">
              <option value="P-256">NIST P-256</option>
              <option value="P-384">NIST P-384</option>
              <option value="P-521">NIST P-521</option>
              <option value="SM2">国密 SM2</option>
              <option value="secp256k1">Bitcoin (secp256k1)</option>
            </select>
            <button @click="genECCKey" class="ck-btn-primary flex-1 justify-center">
              <KeyIcon class="w-3.5 h-3.5" /> 生成密钥
            </button>
          </div>
          <div v-if="eccKeys.privateKey" class="space-y-3 animate-in fade-in duration-300">
            <div>
              <div class="flex justify-between mb-1">
                <label class="ck-label !mb-0 text-amber-400">私钥 (PEM/Hex)</label>
                <button @click="copy(asymKeyFormat === 'pem' ? eccKeys.privateKey : eccKeys.privHex)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="ck-result ck-key-hex !min-h-0 text-amber-300 !text-[10px] break-all max-h-32 overflow-y-auto font-mono">
                {{ asymKeyFormat === 'pem' ? eccKeys.privateKey : eccKeys.privHex }}
              </div>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="ck-label !mb-0 text-cyan-400">公钥 (PEM/Hex)</label>
                <button @click="copy(asymKeyFormat === 'pem' ? eccKeys.publicKey : eccKeys.pubHex)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="ck-result ck-key-hex !min-h-0 text-cyan-300 !text-[10px] break-all max-h-24 overflow-y-auto font-mono">
                {{ asymKeyFormat === 'pem' ? eccKeys.publicKey : eccKeys.pubHex }}
              </div>
            </div>
          </div>
        </div>
        <div class="ck-card space-y-2">
          <div>
            <label class="ck-label">密钥内容 (PEM/Hex)</label>
            <textarea v-model="ecc.key" class="ck-textarea text-[10px] font-mono" rows="3" placeholder="粘贴私钥(签名)或公钥(验签/ECDH)..." />
          </div>
          <div>
            <label class="ck-label">对方公钥 (仅 ECDH 使用)</label>
            <textarea v-model="ecc.peerKey" class="ck-textarea text-[10px] font-mono" rows="2" placeholder="密钥交换时填入对方公钥..." />
          </div>
          <CryptoPanel v-model="ecc.data" label="待处理数据 (Hex)" type="input" clearable />
        </div>
      </div>
      <div class="ck-stack ck-right-panel">
        <div class="grid grid-cols-3 gap-2">
          <button @click="eccSign" class="ck-btn-primary justify-center text-xs"><PenIcon class="w-3.5 h-3.5"/>签名</button>
          <button @click="eccVerify" class="ck-btn-secondary justify-center text-xs"><CheckCircleIcon class="w-3.5 h-3.5"/>验签</button>
          <button @click="ecdhCompute" class="ck-btn-success justify-center text-xs"><LinkIcon class="w-3.5 h-3.5"/>ECDH</button>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="eccResult.data" label="运算结果" type="result" :success="eccResult.success" copyable />
          <div v-if="eccResult.error" class="mt-2 text-xs text-red-400">{{ eccResult.error }}</div>
        </div>
      </div>
    </div>

    <!-- Ed25519 / X25519 -->
    <div v-if="activeTab === 'curve25519'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card">
          <p class="ck-section-title">Curve25519 系列操作</p>
          <div class="flex gap-2 mb-3">
            <button @click="genX25519" class="ck-btn-primary flex-1 text-xs justify-center">
              <KeyIcon class="w-3 h-3" /> X25519 密钥对
            </button>
            <button @click="genEd25519" class="ck-btn-secondary flex-1 text-xs justify-center">
              <KeyIcon class="w-3 h-3" /> Ed25519 密钥对
            </button>
          </div>
          <div v-if="c25519.privateKey" class="space-y-2 animate-in fade-in duration-300">
            <div>
              <label class="ck-label text-amber-400">私钥 (Hex)</label>
              <div class="ck-result ck-key-hex !min-h-0 text-amber-300 text-[10px] font-mono break-all">{{ c25519.privateKey }}</div>
            </div>
            <div>
              <label class="ck-label text-cyan-400">公钥 (Hex)</label>
              <div class="ck-result ck-key-hex !min-h-0 text-cyan-300 text-[10px] font-mono break-all">{{ c25519.publicKey }}</div>
            </div>
          </div>
        </div>
        <div class="ck-card space-y-2">
          <div>
            <label class="ck-label">私钥 (Hex)</label>
            <input v-model="c25519.usePriv" class="ck-input font-mono ck-trim-space text-[10px]" />
          </div>
          <div>
            <label class="ck-label">对方公钥 / 待验证签名 (Hex)</label>
            <input v-model="c25519.peerPub" class="ck-input font-mono ck-trim-space text-[10px]" />
          </div>
          <CryptoPanel v-model="c25519.data" label="待处理数据 (Hex)" type="input" clearable />
        </div>
      </div>
      <div class="ck-stack ck-right-panel">
        <div class="grid grid-cols-2 gap-2">
          <button @click="x25519Exchange" class="ck-btn-primary text-xs justify-center"><LinkIcon class="w-3.5 h-3.5"/>X25519 交换</button>
          <button @click="ed25519Sign" class="ck-btn-success text-xs justify-center"><PenIcon class="w-3.5 h-3.5"/>Ed25519 签名</button>
          <button @click="ed25519Verify" class="ck-btn-secondary col-span-2 text-xs justify-center"><CheckCircleIcon class="w-3.5 h-3.5"/>Ed25519 验签</button>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="c25519Result.data" label="运算结果" type="result" :success="c25519Result.success" copyable />
          <div v-if="c25519Result.error" class="mt-2 text-xs text-red-400">{{ c25519Result.error }}</div>
        </div>
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
import CryptoPanel from '../components/CryptoPanel.vue'
import {
  RSAGenerateKey, RSAEncrypt, RSADecrypt, RSASign, RSAVerify,
  ECCGenerateKey, ECCSign, ECCVerify, ECDHCompute,
  X25519KeyGen, X25519Exchange, Ed25519KeyGen, Ed25519Sign, Ed25519Verify,
  Ed448KeyGen, Ed448Sign, Ed448Verify,
  SM2GenerateKey, SM2Encrypt, SM2Decrypt, SM2Sign, SM2Verify,
  SM9GenerateMasterKey, SM9Sign, SM9Encrypt
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
const rsa = reactive({ bits: 2048, padding: 'OAEP', hash: 'SHA256', key: '', data: '' })
const rsaKeys = reactive({ privateKey: '', publicKey: '', privHex: '', pubHex: '' })
const rsaResult = reactive({ data: '', error: '', success: null })

async function genRSAKey() {
  const r = await RSAGenerateKey(rsa.bits)
  if (r.success) { 
    rsaKeys.privateKey = r.privateKey; rsaKeys.publicKey = r.publicKey 
    rsaKeys.privHex = r.privHex; rsaKeys.pubHex = r.pubHex
    rsa.key = asymKeyFormat.value === 'pem' ? r.publicKey : r.pubHex
  }
}
async function rsaEncrypt() {
  const r = await RSAEncrypt({ key: rsa.key, data: rsa.data, padding: rsa.padding, hash: rsa.hash })
  rsaResult.data = r.data; rsaResult.error = r.error; rsaResult.success = r.success
}
async function rsaDecrypt() {
  const r = await RSADecrypt({ key: rsa.key, data: rsa.data, padding: rsa.padding, hash: rsa.hash })
  rsaResult.data = r.data; rsaResult.error = r.error; rsaResult.success = r.success
}
async function rsaSign() {
  const r = await RSASign({ privateKey: rsa.key, data: rsa.data, hash: rsa.hash, padding: rsa.padding === 'PSS' ? 'PSS' : 'PKCS1v15' })
  rsaResult.data = r.data; rsaResult.error = r.error; rsaResult.success = r.success
}
async function rsaVerify() {
  const r = await RSAVerify({ publicKey: rsa.key, data: rsa.data, signature: rsaResult.data, hash: rsa.hash, padding: rsa.padding === 'PSS' ? 'PSS' : 'PKCS1v15' })
  rsaResult.data = r.data; rsaResult.error = r.error; rsaResult.success = r.success
}

// SM2
const sm2Subtabs = [
  { id: 'keygen', label: '密钥生成' },
  { id: 'enc', label: '加密/解密' },
  { id: 'sign', label: '签名/验签' },
]
const sm2Sub = ref('keygen')
const sm2Keys = reactive({ privateKey: '', publicKey: '', privHex: '', pubHex: '' })
const sm2Enc = reactive({ publicKey: '', privateKey: '', data: '' })
const sm2EncResult = reactive({ data: '', error: '', success: null })
const sm2Sign = reactive({ privateKey: '', publicKey: '', id: '', data: '' })
const sm2SignResult = reactive({ data: '', error: '', success: null })

// ── 统一结果展示 ────────────────────────────────────────────────
const sm2Result = computed(() => {
  if (sm2Sub.value === 'enc') return sm2EncResult
  if (sm2Sub.value === 'sign') return sm2SignResult
  return { data: '', error: '', success: null }
})

async function genSM2Key() {
  const r = await SM2GenerateKey()
  if (r.success) { 
    sm2Keys.privateKey = r.privateKey; sm2Keys.publicKey = r.publicKey 
    sm2Keys.privHex = r.privHex; sm2Keys.pubHex = r.pubHex
    if (asymKeyFormat.value === 'hex') {
      sm2Enc.publicKey = r.pubHex; sm2Enc.privateKey = r.privHex
      sm2Sign.publicKey = r.pubHex; sm2Sign.privateKey = r.privHex
    } else {
      sm2Enc.publicKey = r.publicKey; sm2Enc.privateKey = r.privateKey
      sm2Sign.publicKey = r.publicKey; sm2Sign.privateKey = r.privateKey
    }
  }
}
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
  sm2SignResult.data = r.data; sm2SignResult.error = r.error; sm2SignResult.success = r.success
}
async function doSM2Verify() {
  const r = await SM2Verify({ publicKey: sm2Sign.publicKey, data: sm2Sign.data, signature: sm2SignResult.data, id: sm2Sign.id })
  sm2SignResult.data = r.data; sm2SignResult.error = r.error; sm2SignResult.success = r.success
}

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
