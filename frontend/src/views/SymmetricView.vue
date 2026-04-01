<template>
  <PageLayout title="对称算法" subtitle="AES · DES/3DES · ChaCha20 · 全模式支持"
              icon-bg="bg-blue-500/20"
              :tabs="tabs" :active-tab="activeTab"
              @tab-change="activeTab = $event">
    <template #icon>
      <LockIcon class="w-4 h-4 text-blue-400" />
    </template>

    <template #extra>
      <div class="flex gap-2">
        <button @click="openHelp(activeTab)" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-500/10 text-sky-400 hover:bg-sky-500/20 transition-all text-xs font-medium border border-sky-500/20">
          <InfoIcon class="w-3.5 h-3.5" /> 使用说明
        </button>
        <button @click="showPrinciple = true" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-violet-500/10 text-violet-400 hover:bg-violet-500/20 transition-all text-xs font-medium border border-violet-500/20">
          <ShieldCheckIcon class="w-3.5 h-3.5" /> 算法原理
        </button>
      </div>
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

    <!-- AES Tab -->
    <div v-if="activeTab === 'aes'" class="sym-workbench animate-fade-in">
      <!-- Left: params -->
      <div class="space-y-3 sym-side">
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
              <div class="flex items-center gap-1.5 mb-1">
                <label class="ck-label !mb-0">加密模式</label>
                <button @click="openHelp('aes-mode')" class="ck-mini-trigger"><InfoIcon class="w-3 h-3"/></button>
              </div>
              <select v-model="aes.mode" class="ck-select">
                <option>ECB</option><option>CBC</option><option>CFB</option>
                <option>OFB</option><option>CTR</option><option>GCM</option>
                <option>CCM</option>
              </select>
            </div>
            <div>
              <div class="flex items-center gap-1.5 mb-1">
                <label class="ck-label !mb-0">填充方式</label>
                <button @click="openHelp('aes-padding')" class="ck-mini-trigger"><InfoIcon class="w-3 h-3"/></button>
              </div>
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

        <div class="ck-card space-y-3">
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
      <div class="sym-main">
        <div class="ck-card flex-1 min-h-0 flex flex-col">
          <CryptoPanel v-model="aes.plaintext" label="明文" :placeholder="aes.inputFormat === 'text' ? '输入明文...' : '输入hex格式数据...'"
                       clearable type="textarea" :rows="3" />
          <div v-if="aesLenHint" :class="['mt-1 text-xs', hintClass(aesLenHint)]">{{ aesLenHint }}</div>
          <div class="flex gap-2 shrink-0 mt-3">
            <button @click="encrypt" class="ck-btn-primary flex-1 justify-center py-2" :disabled="aesDisabled">
              <LockIcon class="w-3.5 h-3.5" /> 加密
            </button>
            <button @click="decrypt" class="ck-btn-secondary flex-1 justify-center py-2" :disabled="aesDisabled">
              <UnlockIcon class="w-3.5 h-3.5" /> 解密
            </button>
          </div>
        </div>
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="result.data" label="运算结果 (Hex)" type="result" :success="result.success" copyable />
          <div v-if="result.extra" class="mt-2 animate-in fade-in zoom-in-95 duration-200">
            <div class="flex items-center justify-between mb-1">
              <label class="ck-label !mb-0 text-amber-400">自动生成的 {{ ['GCM','CCM'].includes(aes.mode) ? 'Nonce' : 'IV' }}</label>
              <button @click="copyExtra" class="ck-copy-btn text-amber-400"><CopyIcon class="w-3 h-3" /> 复制</button>
            </div>
            <div class="ck-result !min-h-0 text-amber-300">{{ result.extra }}</div>
          </div>
          <div v-if="result.error" class="mt-2 text-xs text-red-400 flex items-center gap-1 animate-in slide-in-from-top-1">
            <AlertCircleIcon class="w-3.5 h-3.5 shrink-0" /> {{ result.error }}
          </div>
        </div>
        
        <!-- Algorithm Principles - Inline & Detailed -->
        <div class="ck-card bg-gradient-to-br from-violet-500/5 to-transparent border-violet-500/10 shrink-0">
          <p class="ck-section-title text-violet-400">{{ currentPrinciple.title }}</p>
           <div class="text-[11px] space-y-2.5 leading-relaxed opacity-90" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
             <div v-for="(p, i) in currentPrinciple.content.split('\n')" :key="i">
               <p v-if="p.startsWith('•')" class="pl-2.5 flex items-start gap-2">
                 <span class="mt-1.5 w-1 h-1 rounded-full bg-violet-400 shrink-0"></span>
                 <span>{{ p.substring(1).trim() }}</span>
               </p>
               <p v-else-if="p.trim()" :class="p.includes(':') ? 'font-bold text-violet-400/90 mt-1' : ''">{{ p }}</p>
             </div>
           </div>
         </div>
       </div>

     </div>

     <!-- SM4 Tab -->
     <div v-if="activeTab === 'sm4'" class="sym-workbench animate-fade-in">
       <div class="space-y-3 sym-side">
         <div class="ck-card">
           <p class="ck-section-title">算法参数</p>
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
           <p class="ck-section-title">密钥 & 参数</p>
           <div>
             <div class="flex justify-between mb-1">
               <label class="ck-label !mb-0 text-amber-400">密钥 (Key / 16-byte Hex)</label>
               <button @click="genSM4Key" class="text-xs text-violet-400">⚡ 随机生成</button>
             </div>
             <input v-model="sm4.key" class="ck-input font-mono ck-trim-space text-xs" placeholder="输入 32 位 Hex..." />
           </div>
           <div v-if="sm4.mode !== 'ECB' && sm4.mode !== 'GCM'">
             <div class="flex justify-between mb-1">
               <label class="ck-label !mb-0 text-cyan-400">初始化向量 (IV / 16-byte Hex)</label>
               <button @click="genSM4IV" class="text-xs text-violet-400">⚡ 随机生成</button>
             </div>
             <input v-model="sm4.iv" class="ck-input font-mono ck-trim-space text-xs" placeholder="输入 32 位 Hex..." />
           </div>
           <div v-if="sm4.mode === 'GCM'" class="space-y-3">
             <div>
               <div class="flex justify-between mb-1">
                 <label class="ck-label !mb-0 text-cyan-400">Nonce (12-byte Hex)</label>
                 <button @click="genSM4Nonce" class="text-xs text-violet-400">⚡ 随机生成</button>
               </div>
               <input v-model="sm4.nonce" class="ck-input font-mono ck-trim-space text-xs" />
             </div>
             <div>
               <label class="ck-label">附加认证数据 (AAD / 可选 Hex)</label>
               <input v-model="sm4.aad" class="ck-input font-mono ck-trim-space text-xs" />
             </div>
           </div>
         </div>
       </div>
       <div class="sym-main">
         <div class="ck-card flex-1 min-h-0 flex flex-col">
           <CryptoPanel v-model="sm4.data" label="数据 (Hex)" type="textarea" :rows="3" clearable />
           <div class="grid grid-cols-2 gap-2 shrink-0 mt-3">
             <button @click="doSM4Encrypt" class="ck-btn-primary justify-center py-2"><LockIcon class="w-3.5 h-3.5" /> 加密</button>
             <button @click="doSM4Decrypt" class="ck-btn-secondary justify-center py-2"><UnlockIcon class="w-3.5 h-3.5" /> 解密</button>
           </div>
         </div>
         <div class="ck-card shrink-0">
           <CryptoPanel v-model="sm4Result.data" label="运算结果 (Hex)" type="result" :success="sm4Result.success" copyable />
           <div v-if="sm4Result.error" class="mt-2 text-xs text-red-400 animate-in slide-in-from-top-1">{{ sm4Result.error }}</div>
         </div>
         <!-- Principle Card -->
         <div class="ck-card bg-gradient-to-br from-emerald-500/5 to-transparent border-emerald-500/10 shrink-0">
           <p class="ck-section-title text-emerald-400">{{ currentPrinciple.title }}</p>
           <div class="text-[11px] space-y-2.5 leading-relaxed opacity-90" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
             <div v-for="(p, i) in currentPrinciple.content.split('\n')" :key="i">
               <p v-if="p.startsWith('•')" class="pl-2.5 flex items-start gap-2">
                 <span class="mt-1.5 w-1 h-1 rounded-full bg-emerald-400 shrink-0"></span>
                 <span>{{ p.substring(1).trim() }}</span>
               </p>
               <p v-else-if="p.trim()" :class="p.includes(':') ? 'font-bold text-emerald-400/90 mt-1' : ''">{{ p }}</p>
             </div>
           </div>
         </div>
       </div>
     </div>

    <!-- ZUC Tab -->
    <div v-if="activeTab === 'zuc'" class="sym-workbench animate-fade-in">
      <div class="space-y-3 sym-side">
        <div class="ck-card">
          <p class="ck-section-title">算法参数</p>
          <div>
            <label class="ck-label">算法版本</label>
            <select v-model="zuc.type" class="ck-select">
              <option value="ZUC-128">ZUC-128 (4G/LTE)</option>
              <option value="ZUC-256">ZUC-256 (5G 增强)</option>
            </select>
          </div>
        </div>
        <div class="ck-card space-y-3">
          <p class="ck-section-title">密钥 & 参数</p>
          <div>
            <div class="flex justify-between mb-1">
              <label class="ck-label !mb-0 text-amber-400">密钥 (Key / Hex)</label>
              <button @click="genZUCKey" class="text-xs text-violet-400">⚡ 生成</button>
            </div>
            <input v-model="zuc.key" class="ck-input font-mono ck-trim-space text-xs" :placeholder="zuc.type === 'ZUC-256' ? '64位 Hex' : '32位 Hex'" />
          </div>
          <div>
            <div class="flex justify-between mb-1">
              <label class="ck-label !mb-0 text-cyan-400">向量 (IV / Hex)</label>
              <button @click="genZUCIV" class="text-xs text-violet-400">⚡ 生成</button>
            </div>
            <input v-model="zuc.iv" class="ck-input font-mono ck-trim-space text-xs" :placeholder="zuc.type === 'ZUC-256' ? '50位 Hex' : '32位 Hex'" />
          </div>
        </div>
      </div>
      <div class="sym-main">
        <div class="ck-card flex-1 min-h-0 flex flex-col">
          <CryptoPanel v-model="zuc.data" label="待加/解密数据 (Hex)" type="textarea" :rows="3" clearable />
          <button @click="doZUCEncrypt" class="ck-btn-primary w-full justify-center shrink-0 py-2 mt-3 shadow-lg shadow-violet-500/10">
            <ZapIcon class="w-3.5 h-3.5" /> 执行 ZUC 变换
          </button>
        </div>
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="zucResult.data" label="变换结果 (Hex)" type="result" :success="zucResult.success" copyable />
          <div v-if="zucResult.error" class="mt-2 text-xs text-red-400 animate-in slide-in-from-top-1">{{ zucResult.error }}</div>
        </div>
        <!-- Principle Card -->
        <div class="ck-card bg-gradient-to-br from-violet-500/5 to-transparent border-violet-500/10 shrink-0">
          <p class="ck-section-title text-violet-400">{{ currentPrinciple.title }}</p>
          <div class="text-[11px] space-y-2.5 leading-relaxed opacity-90" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div v-for="(p, i) in currentPrinciple.content.split('\n')" :key="i">
              <p v-if="p.startsWith('•')" class="pl-2.5 flex items-start gap-2">
                <span class="mt-1.5 w-1 h-1 rounded-full bg-violet-400 shrink-0"></span>
                <span>{{ p.substring(1).trim() }}</span>
              </p>
              <p v-else-if="p.trim()" :class="p.includes(':') ? 'font-bold text-violet-400/90 mt-1' : ''">{{ p }}</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Envelope Tab -->
    <div v-if="activeTab === 'envelope'" class="sym-workbench animate-fade-in">
      <div class="sym-side space-y-3 overflow-y-auto pr-1 custom-scrollbar">
        <div class="ck-card space-y-4">
          <p class="ck-section-title">制作数字信封 (密封)</p>
          <div class="space-y-3">
            <div>
              <label class="ck-label text-amber-400 text-[11px]">发送方私钥 (PEM/Hex)</label>
              <textarea v-model="envelope.senderPriv" class="ck-textarea text-[10px] font-mono" rows="2" placeholder="SM2 Private Key..."></textarea>
            </div>
            <div>
              <label class="ck-label text-cyan-400 text-[11px]">接收方公钥 (PEM/Hex)</label>
              <textarea v-model="envelope.receiverPub" class="ck-textarea text-[10px] font-mono" rows="2" placeholder="SM2 Public Key..."></textarea>
            </div>
            <button @click="makeEnvelope" class="ck-btn-primary w-full justify-center shadow-lg shadow-violet-500/10">
              <PackageIcon class="w-3.5 h-3.5" /> 制作并导出信封
            </button>
          </div>
        </div>
        <div class="ck-card space-y-4">
          <p class="ck-section-title">拆解数字信封 (开封)</p>
          <div class="space-y-3">
            <div>
              <label class="ck-label text-amber-400 text-[11px]">接收方私钥 (PEM/Hex)</label>
              <textarea v-model="envelope.receiverPriv" class="ck-textarea text-[10px] font-mono" rows="2" placeholder="SM2 Private Key..."></textarea>
            </div>
            <div>
              <label class="ck-label text-cyan-400 text-[11px]">发送方公钥 (PEM/Hex)</label>
              <textarea v-model="envelope.senderPub" class="ck-textarea text-[10px] font-mono" rows="2" placeholder="SM2 Public Key..."></textarea>
            </div>
            <button @click="openEnvelope" class="ck-btn-secondary w-full justify-center">
              <PackageOpenIcon class="w-3.5 h-3.5" /> 拆解并验证数据
            </button>
          </div>
        </div>
      </div>
      <div class="sym-main h-full flex flex-col">
        <div class="ck-card flex-1 min-h-0 flex flex-col">
          <p class="ck-section-title">报文数据</p>
          <CryptoPanel v-model="envelope.data" label="待密封数据 / 待拆解信封 (Hex)" type="textarea" :rows="4" clearable />
        </div>
        <div class="ck-card shrink-0 mt-3">
          <CryptoPanel v-model="envelopeResult.data" label="处理结果 (Hex)" type="result" :success="envelopeResult.success" copyable />
          <div v-if="envelopeResult.error" class="mt-2 text-xs text-red-400 animate-in slide-in-from-top-1">{{ envelopeResult.error }}</div>
        </div>
        <!-- Principle Card -->
        <div class="ck-card bg-gradient-to-br from-violet-500/5 to-transparent border-violet-500/10 shrink-0 mt-3">
          <p class="ck-section-title text-violet-400">数字信封原理 (SM2+SM4)</p>
          <div class="text-[11px] space-y-2.5 leading-relaxed opacity-90" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div v-for="(p, i) in principles.envelope.content.split('\n')" :key="i">
              <p v-if="p.startsWith('•')" class="pl-2.5 flex items-start gap-2">
                <span class="mt-1.5 w-1 h-1 rounded-full bg-violet-400 shrink-0"></span>
                <span>{{ p.substring(1).trim() }}</span>
              </p>
              <p v-else-if="p.trim()" :class="p.includes(':') ? 'font-bold text-violet-400/90 mt-1' : ''">{{ p }}</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- DES Tab -->
    <div v-if="activeTab === 'des'" class="sym-workbench animate-fade-in">
      <!-- Left: params -->
      <div class="space-y-3 sym-side">
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
        <div class="ck-card space-y-3">
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
      <div class="space-y-3 sym-main">
        <div class="ck-card">
          <CryptoPanel v-model="des.plaintext" label="明文 (hex)" clearable type="textarea" :rows="3" />
          <div v-if="desLenHint" :class="['mt-1 text-xs', hintClass(desLenHint)]">{{ desLenHint }}</div>
        </div>
        <div class="flex gap-2 shrink-0">
          <button @click="desEncrypt" class="ck-btn-primary flex-1 justify-center" :disabled="desDisabled"><LockIcon class="w-3.5 h-3.5" /> 加密</button>
          <button @click="desDecrypt" class="ck-btn-secondary flex-1 justify-center" :disabled="desDisabled"><UnlockIcon class="w-3.5 h-3.5" /> 解密</button>
          <button @click="openHelp('des')" class="ck-btn-muted justify-center px-3">说明</button>
        </div>
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="desResult.data" label="结果 (hex)" type="result" :success="desResult.success" copyable />
          <div v-if="desResult.error" class="mt-2 text-xs text-red-400">{{ desResult.error }}</div>
        </div>
      </div>

    </div>

    <!-- ChaCha20 Tab -->
    <div v-if="activeTab === 'chacha'" class="sym-workbench animate-fade-in">
      <!-- Left: params -->
      <div class="space-y-3 sym-side">
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
        <div class="ck-card space-y-3">
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
      <div class="sym-main">
        <div class="ck-card flex-1 min-h-0 flex flex-col">
          <CryptoPanel v-model="chacha.data" label="数据 (Hex)" clearable type="textarea" :rows="3" />
          <div v-if="chachaLenHint" :class="['mt-1 text-xs', hintClass(chachaLenHint)]">{{ chachaLenHint }}</div>
          <div class="flex gap-2 shrink-0 mt-3">
            <button @click="chachaEncrypt" class="ck-btn-primary flex-1 justify-center py-2" :disabled="chachaDisabled"><LockIcon class="w-3.5 h-3.5" /> 加密</button>
            <button @click="chachaDecrypt" class="ck-btn-secondary flex-1 justify-center py-2" :disabled="chachaDisabled"><UnlockIcon class="w-3.5 h-3.5" /> 解密</button>
            <button @click="openHelp('chacha')" class="ck-btn-secondary px-3" title="详细帮助"><InfoIcon class="w-3.5 h-3.5" /></button>
          </div>
        </div>
        <div class="ck-card shrink-0">
          <CryptoPanel v-model="chachaResult.data" label="运算结果 (Hex)" type="result" :success="chachaResult.success" copyable />
          <div v-if="chachaResult.extra" class="mt-2 text-[10px] text-amber-400 font-mono bg-amber-500/5 p-1.5 rounded border border-amber-500/10">自动生成 Nonce: {{ chachaResult.extra }}</div>
          <div v-if="chachaResult.error" class="mt-2 text-xs text-red-400 animate-in slide-in-from-top-1">{{ chachaResult.error }}</div>
        </div>
        <!-- Principle Card -->
        <div class="ck-card bg-gradient-to-br from-violet-500/5 to-transparent border-violet-500/10 shrink-0">
          <p class="ck-section-title text-violet-400">{{ currentPrinciple.title }}</p>
          <div class="text-[11px] space-y-2.5 leading-relaxed opacity-90" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div v-for="(p, i) in currentPrinciple.content.split('\n')" :key="i">
              <p v-if="p.startsWith('•')" class="pl-2.5 flex items-start gap-2">
                <span class="mt-1.5 w-1 h-1 rounded-full bg-violet-400 shrink-0"></span>
                <span>{{ p.substring(1).trim() }}</span>
              </p>
              <p v-else-if="p.trim()" :class="p.includes(':') ? 'font-bold text-violet-400/90 mt-1' : ''">{{ p }}</p>
            </div>
          </div>
        </div>
      </div>

    </div>

    <!-- RC4 Tab -->
    <div v-if="activeTab === 'rc4'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
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
          <CryptoPanel v-model="rc4.data" label="数据 (hex)" type="textarea" :rows="3" clearable />
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

      <div class="ck-stack ck-right-panel h-full flex flex-col">
        <div class="ck-card flex-1 min-h-0">
          <CryptoPanel v-model="rc4Result.data" label="运算结果 (Hex)" type="result" :success="rc4Result.success" copyable />
          <div v-if="rc4Result.error" class="mt-2 text-xs text-red-400 animate-in slide-in-from-top-1">{{ rc4Result.error }}</div>
        </div>
        <!-- Principle Card -->
        <div class="ck-card bg-gradient-to-br from-violet-500/5 to-transparent border-violet-500/10 shrink-0 mt-3">
          <p class="ck-section-title text-violet-400">{{ currentPrinciple.title }}</p>
          <div class="text-[11px] space-y-2.5 leading-relaxed opacity-90" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div v-for="(p, i) in currentPrinciple.content.split('\n')" :key="i">
              <p v-if="p.startsWith('•')" class="pl-2.5 flex items-start gap-2">
                <span class="mt-1.5 w-1 h-1 rounded-full bg-violet-400 shrink-0"></span>
                <span>{{ p.substring(1).trim() }}</span>
              </p>
              <p v-else-if="p.trim()" :class="p.includes(':') ? 'font-bold text-violet-400/90 mt-1' : ''">{{ p }}</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- SIV Tab -->
    <div v-if="activeTab === 'siv'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
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
          <CryptoPanel v-model="siv.data" label="数据 (hex)" type="textarea" :rows="3" clearable />
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

      <div class="ck-stack ck-right-panel h-full flex flex-col">
        <div class="ck-card flex-1 min-h-0">
          <CryptoPanel v-model="sivResult.data" label="运算结果 (Hex)" type="result" :success="sivResult.success" copyable />
          <div v-if="sivResult.error" class="mt-2 text-xs text-red-400 animate-in slide-in-from-top-1">{{ sivResult.error }}</div>
        </div>
        <!-- Principle Card -->
        <div class="ck-card bg-gradient-to-br from-violet-500/5 to-transparent border-violet-500/10 shrink-0 mt-3">
          <p class="ck-section-title text-violet-400">{{ currentPrinciple.title }}</p>
          <div class="text-[11px] space-y-2.5 leading-relaxed opacity-90" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div v-for="(p, i) in currentPrinciple.content.split('\n')" :key="i">
              <p v-if="p.startsWith('•')" class="pl-2.5 flex items-start gap-2">
                <span class="mt-1.5 w-1 h-1 rounded-full bg-violet-400 shrink-0"></span>
                <span>{{ p.substring(1).trim() }}</span>
              </p>
              <p v-else-if="p.trim()" :class="p.includes(':') ? 'font-bold text-violet-400/90 mt-1' : ''">{{ p }}</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- FPE Tab -->
    <div v-if="activeTab === 'fpe'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
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
          <CryptoPanel v-model="fpe.data" label="待处理数据" type="textarea" :rows="3" clearable />
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

      <div class="ck-stack ck-right-panel h-full flex flex-col">
        <div class="ck-card flex-1 min-h-0">
          <CryptoPanel v-model="fpeResult.data" label="运算结果" type="result" :success="fpeResult.success" copyable />
          <div v-if="fpeResult.error" class="mt-2 text-xs text-red-400 animate-in slide-in-from-top-1">{{ fpeResult.error }}</div>
        </div>
        <!-- Principle Card -->
        <div class="ck-card bg-gradient-to-br from-violet-500/5 to-transparent border-violet-500/10 shrink-0 mt-3">
          <p class="ck-section-title text-violet-400">{{ currentPrinciple.title }}</p>
          <div class="text-[11px] space-y-2.5 leading-relaxed opacity-90" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div v-for="(p, i) in currentPrinciple.content.split('\n')" :key="i">
              <p v-if="p.startsWith('•')" class="pl-2.5 flex items-start gap-2">
                <span class="mt-1.5 w-1 h-1 rounded-full bg-violet-400 shrink-0"></span>
                <span>{{ p.substring(1).trim() }}</span>
              </p>
              <p v-else-if="p.trim()" :class="p.includes(':') ? 'font-bold text-violet-400/90 mt-1' : ''">{{ p }}</p>
            </div>
            <p class="pt-1 opacity-70 italic font-mono text-[9px]">输入限制: 长度 ≥ {{ fpeMinLen }}；最大 {{ fpeMaxLen }}</p>
          </div>
        </div>
      </div>
    </div>

    <transition name="fade">
      <div v-if="helpOpen" class="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" @click.self="helpOpen = false">
        <div class="help-modal animate-in zoom-in-95 duration-200"
             @click.stop>
          <div class="flex justify-between items-center px-5 pt-5 pb-3 border-b" :class="isDark ? 'border-dark-border' : 'border-slate-200'">
            <h3 class="text-[15px] font-semibold flex items-center gap-2">
              <InfoIcon class="w-4 h-4 text-sky-400" /> {{ helpTitle }}
            </h3>
            <button @click="helpOpen = false" class="p-1.5 hover:bg-gray-100 dark:hover:bg-dark-hover rounded-md transition-colors">
              <XIcon class="w-4 h-4 text-dark-muted" />
            </button>
          </div>
          <div class="px-5 pt-4 pb-5 text-[13px] leading-6 space-y-4" :class="isDark ? 'text-dark-muted' : 'text-slate-600'">
            <template v-if="helpType === 'aes'">
              <div class="help-hero">
                <p class="text-sm font-semibold mb-1" :class="isDark ? 'text-white' : 'text-slate-900'">AES 是现代默认对称算法</p>
                <p>当前配置为 <span class="help-inline-kbd">AES-{{ aes.keySize }}</span> + <span class="help-inline-kbd">{{ aes.mode }}</span>。如果你只是做常规业务加密，优先用 GCM；如果要兼容旧系统，再考虑 CBC。</p>
              </div>
              <div class="help-grid">
                <div class="help-note">
                  <p class="help-note-title">输入与填充</p>
                  <p>Hex 输入必须是偶数位；使用 <span class="help-inline-kbd">NoPadding</span> 时，数据长度必须正好是 16 字节的倍数。</p>
                </div>
                <div class="help-note">
                  <p class="help-note-title">密钥与参数</p>
                  <p>ECB 不需要 IV；CBC/CFB/OFB/CTR 通常需要 IV；GCM/CCM 使用 Nonce，可选再附加 AAD 做认证保护。</p>
                </div>
              </div>
              <div class="help-note">
                <p class="help-note-title">{{ aes.mode }} 模式怎么选</p>
                <p v-if="aes.mode === 'ECB'">每个分组独立处理，最容易理解，但会暴露重复明文块的结构，只适合测试或兼容旧接口，不建议业务数据直接使用。</p>
                <p v-else-if="aes.mode === 'CBC'">传统工程里最常见的模式之一，兼容性强，适合文件和数据库场景。注意 IV 不能重复，且通常需要配合额外 MAC 才能防篡改。</p>
                <p v-else-if="aes.mode === 'CFB'">把分组密码转换成流式处理方式，不要求块对齐，适合边到边传输，但新项目里通常会优先考虑更现代的 CTR 或 GCM。</p>
                <p v-else-if="aes.mode === 'OFB'">通过独立密钥流工作，位错误不会连带扩散，但也因此更依赖正确的参数管理，工程上没有 GCM 那么常见。</p>
                <p v-else-if="aes.mode === 'CTR'">性能好、可并行、支持随机访问，适合高吞吐处理；但它只负责机密性，不负责完整性，通常要再配认证机制。</p>
                <p v-else-if="aes.mode === 'GCM'">现代首选。一次完成加密和完整性校验，适合接口、会话、文件交换等绝大多数业务场景，只要保证 Nonce 不重复即可。</p>
                <p v-else-if="aes.mode === 'CCM'">同样是认证加密，常见于嵌入式、无线和 IoT 协议。它更偏标准化场景，但对消息长度和处理方式限制也更多。</p>
              </div>
              <div class="help-grid">
                <div class="help-note">
                  <p class="help-note-title">实战建议</p>
                  <p>新项目优先选 GCM；兼容旧系统选 CBC；如果要流式高性能处理可考虑 CTR，但要额外补完整性校验。</p>
                </div>
                <div class="help-note">
                  <p class="help-note-title">常见误区</p>
                  <p>不要重复使用同一组 Key + IV/Nonce；不要把 ECB 当通用模式；不要在 NoPadding 下直接喂任意长度数据。</p>
                </div>
              </div>
            </template>
            <template v-else-if="helpType === 'des'">
              <div class="help-hero">
                <p class="text-sm font-semibold mb-1" :class="isDark ? 'text-white' : 'text-slate-900'">{{ des.type === 'DES' ? 'DES 已属于遗留算法' : '3DES 主要用于老系统兼容' }}</p>
                <p v-if="des.type === 'DES'">它现在更适合教学或历史数据兼容，不应再作为新系统的正式加密方案。</p>
                <p v-else>3DES 还能在部分金融或遗留设备中见到，但性能和安全边界都明显落后于 AES。</p>
              </div>
              <div class="help-grid">
                <div class="help-note">
                  <p class="help-note-title">模式选择</p>
                  <p v-if="des.mode === 'ECB'">ECB 不需要 IV，但会直接暴露重复块形状，除非做兼容测试，否则不建议用。</p>
                  <p v-else-if="des.mode === 'CBC'">CBC 是遗留系统里最常见的选项，兼容性相对最好，也是这类算法里最稳妥的工程选择。</p>
                  <p v-else-if="des.mode === 'CFB'">CFB 可以做流式处理，不要求块对齐，更适合持续输入输出的旧式通道加密。</p>
                  <p v-else-if="des.mode === 'OFB'">OFB 使用独立密钥流，错误不扩散，但现在实际场景已经不多。</p>
                  <p v-else-if="des.mode === 'CTR'">CTR 让旧算法也能做并行处理，不过如果能选，通常应直接换到 AES-CTR 或 AES-GCM。</p>
                </div>
                <div class="help-note">
                  <p class="help-note-title">迁移建议</p>
                  <p>如果你现在还在处理 DES / 3DES，最好把它理解成“兼容接口工具”而不是“主力算法页”，新系统应优先迁移到 AES。</p>
                </div>
              </div>
            </template>
            <template v-else-if="helpType === 'chacha'">
              <div class="help-hero">
                <p class="text-sm font-semibold mb-1" :class="isDark ? 'text-white' : 'text-slate-900'">{{ chacha.type }}</p>
                <p>ChaCha20 系列在纯软件环境下速度非常好，特别适合移动端、容器环境或没有 AES 硬件加速的场景。</p>
              </div>
              <div class="help-grid">
                <div class="help-note">
                  <p class="help-note-title">参数要点</p>
                  <p>密钥固定 32 字节；普通版 Nonce 通常为 12 字节；XChaCha20 扩展到 24 字节，更适合大规模随机生成 Nonce 的场景。</p>
                </div>
                <div class="help-note">
                  <p class="help-note-title">什么时候选它</p>
                  <p>如果你在意跨平台软件性能、实现简洁度和现代协议兼容性，ChaCha20-Poly1305 往往是非常好的选择。</p>
                </div>
              </div>
              <div v-if="chacha.type.includes('Poly1305')" class="help-note">
                <p class="help-note-title">Poly1305 认证</p>
                <p>带 Poly1305 的版本不只是“加密”，还会一起校验消息是否被改过，因此更适合接口请求、会话数据和安全通信。</p>
              </div>
            </template>
          </div>
          <div class="px-5 pb-5 flex justify-end">
            <button @click="helpOpen = false" class="ck-btn-muted px-5">关闭</button>
          </div>
        </div>
      </div>
    </transition>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useRoute } from 'vue-router'
import { LockIcon, UnlockIcon, CopyIcon, AlertCircleIcon, InfoIcon, XIcon, ZapIcon, PackageIcon, PackageOpenIcon, ShieldCheckIcon } from 'lucide-vue-next'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import {
  AESEncrypt, AESDecrypt, DESEncrypt, DESDecrypt, ChaCha20Encrypt, ChaCha20Decrypt,
  RC4Encrypt, RC4Decrypt, SIVEncrypt, SIVDecrypt, FPEEncrypt, FPEDecrypt,
  SM4Encrypt, SM4Decrypt, ZUCEncrypt, MakeGMEnvelope, OpenGMEnvelope
} from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

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

// ── 算法原理 ────────────────────────────────────────────────
const showPrinciple = ref(false)
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
const currentPrinciple = computed(() => principles[activeTab.value])

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
const helpOpen = ref(false)
const helpType = ref('aes')
const helpTitle = computed(() => {
  if (helpType.value === 'des') return `${des.type} 使用说明`
  if (helpType.value === 'chacha') return `${chacha.type} 使用说明`
  if (helpType.value === 'sm4') return 'SM4 算法使用说明'
  if (helpType.value === 'zuc') return 'ZUC 算法使用说明'
  if (helpType.value === 'envelope') return '数字信封操作说明'
  if (helpType.value === 'rc4') return 'RC4 使用说明'
  if (helpType.value === 'siv') return 'AES-SIV 使用说明'
  if (helpType.value === 'fpe') return 'FPE 格式保持加密说明'
  return `AES-${aes.keySize} ${aes.mode} 使用说明`
})

function openHelp(type) {
  helpType.value = type
  helpOpen.value = true
}

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
  sm4Result.data = r.data; sm4Result.error = r.error; sm4Result.extra = r.extra; sm4Result.success = r.success
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

<style scoped>
.sym-workbench {
  display: grid;
  grid-template-columns: minmax(460px, 1.4fr) 1fr;
  gap: 16px;
  align-items: start;
}

@media (min-width: 1440px) {
  .sym-workbench {
    grid-template-columns: minmax(520px, 1.5fr) 1fr;
    gap: 24px;
  }
}

.sym-side,
.sym-main {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

@media (max-width: 1080px) {
  .sym-workbench {
    grid-template-columns: 1fr;
  }
}
</style>
