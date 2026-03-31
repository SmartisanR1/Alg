<template>
  <PageLayout title="后量子密码 (PQC)" subtitle="FIPS 203 ML-KEM · FIPS 204 ML-DSA · FIPS 205 SLH-DSA"
              icon-bg="bg-purple-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <AtomIcon class="w-4 h-4 text-purple-400" />
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

    <!-- ML-KEM -->
    <div v-if="activeTab === 'mlkem'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <div class="ck-card">
          <div class="flex items-center gap-2 mb-3">
            <span class="ck-badge-purple">FIPS 203</span>
            <p class="text-sm font-medium">ML-KEM (Kyber) — 密钥封装机制</p>
          </div>
          <div>
            <label class="ck-label">参数集</label>
            <select v-model="kem.paramSet" class="ck-select mb-3">
              <option value="ML-KEM-512">ML-KEM-512 (128位安全)</option>
              <option value="ML-KEM-768" selected>ML-KEM-768 (192位安全)</option>
              <option value="ML-KEM-1024">ML-KEM-1024 (256位安全)</option>
            </select>
          </div>
          <button @click="genKEMKey" class="ck-btn-primary w-full justify-center mb-3">
            <KeyIcon class="w-3.5 h-3.5" /> 生成密钥对
          </button>
          <div v-if="kemKeys.publicKey" class="space-y-2 flex-1 min-h-0 flex flex-col">
            <div class="flex-1 min-h-0 flex flex-col">
              <div class="flex justify-between mb-1 shrink-0">
                <label class="ck-label !mb-0 text-amber-400">私钥 (Private Key)</label>
                <button @click="copy(kemKeys.privateKey)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <textarea readonly class="ck-result ck-key-hex !min-h-[96px] text-amber-300 text-[10px] font-mono w-full flex-1 resize-none bg-transparent outline-none border-none overflow-y-auto" :value="kemKeys.privateKey"></textarea>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                  {{ base64ByteLen(kemKeys.privateKey) + ' bytes' }}
                </span>
              </div>
            </div>
            <div class="flex-1 min-h-0 flex flex-col mt-2">
              <div class="flex justify-between mb-1 shrink-0">
                <label class="ck-label !mb-0 text-cyan-400">公钥 (Public Key)</label>
                <button @click="copy(kemKeys.publicKey)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <textarea readonly class="ck-result ck-key-hex !min-h-[96px] text-cyan-300 text-[10px] font-mono w-full flex-1 resize-none bg-transparent outline-none border-none overflow-y-auto" :value="kemKeys.publicKey"></textarea>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-cyan-400 border-cyan-500/20 bg-cyan-500/5">
                  {{ base64ByteLen(kemKeys.publicKey) + ' bytes' }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="space-y-3 ck-right-panel">
        <div class="ck-card space-y-3">
          <button @click="kemEncap" :disabled="!kemKeys.publicKey" class="ck-btn-success w-full justify-center">
            <LockIcon class="w-3.5 h-3.5" /> 封装 (Encapsulate)
          </button>
          <div v-if="kemEncapResult.ciphertext" class="space-y-2">
            <div>
              <label class="ck-label text-emerald-400">密文 (Ciphertext)</label>
              <div class="ck-result text-emerald-300 text-[10px]">{{ kemEncapResult.ciphertext?.slice(0,80) }}...</div>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="ck-label !mb-0 text-yellow-400">共享密钥 (Shared Secret)</label>
                <button @click="copy(kemEncapResult.sharedSecret)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="ck-result text-yellow-300 font-mono">{{ kemEncapResult.sharedSecret }}</div>
            </div>
          </div>
        </div>

        <div class="ck-card space-y-3">
          <button @click="kemDecap" :disabled="!kemKeys.privateKey || !kemEncapResult.ciphertext"
                  class="ck-btn-secondary w-full justify-center">
            <UnlockIcon class="w-3.5 h-3.5" /> 解封装 (Decapsulate)
          </button>
          <div v-if="kemDecapResult.data">
            <div class="flex justify-between mb-1">
              <label class="ck-label !mb-0 text-yellow-400">恢复的共享密钥</label>
              <button @click="copy(kemDecapResult.data)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
            </div>
            <div class="ck-result text-yellow-300 font-mono">{{ kemDecapResult.data }}</div>
            <div class="mt-2 text-xs flex items-center gap-1"
                 :class="kemEncapResult.sharedSecret === kemDecapResult.data ? 'text-emerald-400' : 'text-red-400'">
              <CheckCircleIcon v-if="kemEncapResult.sharedSecret === kemDecapResult.data" class="w-3.5 h-3.5" />
              <XCircleIcon v-else class="w-3.5 h-3.5" />
              {{ kemEncapResult.sharedSecret === kemDecapResult.data ? '✅ 共享密钥一致！密钥交换成功' : '❌ 共享密钥不匹配' }}
            </div>
          </div>
        </div>

        <div class="ck-card">
          <p class="ck-section-title">参数对比</p>
          <table class="w-full text-xs">
            <thead>
              <tr :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
                <th class="text-left pb-1">参数集</th>
                <th class="text-right pb-1">公钥</th>
                <th class="text-right pb-1">密文</th>
                <th class="text-right pb-1">安全级别</th>
              </tr>
            </thead>
            <tbody :class="isDark ? 'text-dark-text' : 'text-light-text'">
              <tr v-for="r in kemParams" :key="r.name" class="border-t"
                  :class="[isDark ? 'border-dark-border' : 'border-light-border',
                           kem.paramSet === r.name ? (isDark ? 'text-violet-300' : 'text-violet-600') : '']">
                <td class="py-1 font-mono">{{ r.name }}</td>
                <td class="text-right">{{ r.pubKey }}</td>
                <td class="text-right">{{ r.ct }}</td>
                <td class="text-right">{{ r.security }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ML-DSA -->
    <div v-if="activeTab === 'mldsa'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <div class="ck-card">
          <div class="flex items-center gap-2 mb-3">
            <span class="ck-badge-cyan">FIPS 204</span>
            <p class="text-sm font-medium">ML-DSA (Dilithium) — 数字签名</p>
          </div>
          <label class="ck-label">参数集</label>
          <select v-model="dsa.paramSet" class="ck-select mb-3">
            <option value="ML-DSA-44">ML-DSA-44 (128位安全)</option>
            <option value="ML-DSA-65" selected>ML-DSA-65 (192位安全)</option>
            <option value="ML-DSA-87">ML-DSA-87 (256位安全)</option>
          </select>
          <button @click="genDSAKey" class="ck-btn-primary w-full justify-center mb-3">
            <KeyIcon class="w-3.5 h-3.5" /> 生成签名密钥对
          </button>
          <div v-if="dsaKeys.publicKey" class="space-y-2 flex-1 min-h-0 flex flex-col">
            <div class="flex-1 min-h-0 flex flex-col">
              <label class="ck-label text-amber-400 shrink-0">私钥 (Private Key)</label>
              <textarea readonly class="ck-result ck-key-hex !min-h-[96px] text-amber-300 text-[10px] font-mono w-full flex-1 resize-none bg-transparent outline-none border-none overflow-y-auto" :value="dsaKeys.privateKey"></textarea>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                  {{ base64ByteLen(dsaKeys.privateKey) + ' bytes' }}
                </span>
              </div>
            </div>
            <div class="flex-1 min-h-0 flex flex-col mt-2">
              <label class="ck-label text-cyan-400 shrink-0">公钥 (Public Key)</label>
              <textarea readonly class="ck-result ck-key-hex !min-h-[96px] text-cyan-300 text-[10px] font-mono w-full flex-1 resize-none bg-transparent outline-none border-none overflow-y-auto" :value="dsaKeys.publicKey"></textarea>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-cyan-400 border-cyan-500/20 bg-cyan-500/5">
                  {{ base64ByteLen(dsaKeys.publicKey) + ' bytes' }}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="dsa.data" label="待签名数据 (hex)" type="textarea" :rows="3" clearable />
        </div>
      </div>

      <div class="space-y-3 ck-right-panel">
        <div class="flex gap-2">
          <button @click="dsaSign" :disabled="!dsaKeys.privateKey" class="ck-btn-primary flex-1 justify-center">
            <PenIcon class="w-3.5 h-3.5" /> 签名
          </button>
          <button @click="dsaVerify" :disabled="!dsaKeys.publicKey || !dsaResult.data"
                  class="ck-btn-secondary flex-1 justify-center">
            <CheckCircleIcon class="w-3.5 h-3.5" /> 验签
          </button>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="dsaResult.data" label="签名 (hex, 截断显示)" type="result"
                       :success="dsaResult.success" copyable />
          <div v-if="dsaResult.error" class="mt-2 text-xs"
               :class="dsaResult.data === 'true' ? 'text-emerald-400' : 'text-red-400'">
            {{ dsaResult.error || (dsaResult.data === 'true' ? '✅ 签名验证通过' : '') }}
          </div>
        </div>
        <div class="ck-card">
          <p class="ck-section-title">参数对比</p>
          <table class="w-full text-xs">
            <thead><tr :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
              <th class="text-left pb-1">参数集</th>
              <th class="text-right pb-1">公钥</th>
              <th class="text-right pb-1">签名</th>
              <th class="text-right pb-1">安全</th>
            </tr></thead>
            <tbody :class="isDark ? 'text-dark-text' : 'text-light-text'">
              <tr v-for="r in dsaParams" :key="r.name" class="border-t"
                  :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <td class="py-1 font-mono">{{ r.name }}</td>
                <td class="text-right">{{ r.pubKey }}</td>
                <td class="text-right">{{ r.sig }}</td>
                <td class="text-right">{{ r.security }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- SLH-DSA -->
    <div v-if="activeTab === 'slhdsa'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <div class="ck-card">
          <div class="flex items-center gap-2 mb-3">
            <span class="ck-badge-green">FIPS 205</span>
            <p class="text-sm font-medium">SLH-DSA (SPHINCS+) — 无状态签名</p>
          </div>
          <label class="ck-label">参数集</label>
          <select v-model="slh.paramSet" class="ck-select mb-3">
            <option v-for="p in slhParams" :key="p.name" :value="p.name">
              {{ p.name }} ({{ p.security }})
            </option>
          </select>
          <button @click="genSLHKey" class="ck-btn-primary w-full justify-center mb-3">
            <KeyIcon class="w-3.5 h-3.5" /> 生成签名密钥对
          </button>
          <div v-if="slhKeys.publicKey" class="space-y-2 flex-1 min-h-0 flex flex-col">
            <div class="flex-1 min-h-0 flex flex-col">
              <label class="ck-label text-amber-400 shrink-0">私钥 (Private Key)</label>
              <textarea readonly class="ck-result ck-key-hex !min-h-[80px] text-amber-300 text-[10px] font-mono w-full flex-1 resize-none bg-transparent outline-none border-none overflow-y-auto" :value="slhKeys.privateKey"></textarea>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                  {{ base64ByteLen(slhKeys.privateKey) + ' bytes' }}
                </span>
              </div>
            </div>
            <div class="flex-1 min-h-0 flex flex-col mt-2">
              <label class="ck-label text-cyan-400 shrink-0">公钥 (Public Key)</label>
              <textarea readonly class="ck-result ck-key-hex !min-h-[80px] text-cyan-300 text-[10px] font-mono w-full flex-1 resize-none bg-transparent outline-none border-none overflow-y-auto" :value="slhKeys.publicKey"></textarea>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-cyan-400 border-cyan-500/20 bg-cyan-500/5">
                  {{ base64ByteLen(slhKeys.publicKey) + ' bytes' }}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="slh.data" label="待签名数据 (hex)" type="textarea" :rows="3" clearable />
        </div>
      </div>

      <div class="space-y-3 ck-right-panel">
        <div class="flex gap-2">
          <button @click="slhSign" :disabled="!slhKeys.privateKey" class="ck-btn-primary flex-1 justify-center">
            <PenIcon class="w-3.5 h-3.5" /> 签名
          </button>
          <button @click="slhVerify" :disabled="!slhKeys.publicKey || !slhResult.data"
                  class="ck-btn-secondary flex-1 justify-center">
            <CheckCircleIcon class="w-3.5 h-3.5" /> 验签
          </button>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="slhResult.data" label="签名 (hex, 截断显示)" type="result"
                       :success="slhResult.success" copyable />
          <div v-if="slhResult.error" class="mt-2 text-xs"
               :class="slhResult.data === 'true' ? 'text-emerald-400' : 'text-red-400'">
            {{ slhResult.error || (slhResult.data === 'true' ? '✅ 签名验证通过' : '') }}
          </div>
        </div>
        <div class="ck-card">
          <p class="ck-section-title">参数对比</p>
          <div class="overflow-x-auto">
            <table class="w-full text-xs">
              <thead><tr :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
                <th class="text-left pb-1">参数集</th>
                <th class="text-right pb-1">公钥</th>
                <th class="text-right pb-1">签名</th>
                <th class="text-right pb-1">安全</th>
              </tr></thead>
              <tbody :class="isDark ? 'text-dark-text' : 'text-light-text'">
                <tr v-for="r in slhParams" :key="r.name" class="border-t"
                    :class="[isDark ? 'border-dark-border' : 'border-light-border',
                             slh.paramSet === r.name ? (isDark ? 'text-emerald-300' : 'text-emerald-600') : '']">
                  <td class="py-1 font-mono text-[10px]">{{ r.name }}</td>
                  <td class="text-right">{{ r.pubKey }}</td>
                  <td class="text-right">{{ r.sig }}</td>
                  <td class="text-right">{{ r.security }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- FALCON — 调研预览 -->
    <div v-if="activeTab === 'falcon'" class="ck-workbench animate-fade-in">
      <!-- 左列: 算法说明 + 参数预览 -->
      <div class="ck-stack">
        <!-- 状态横幅 -->
        <div class="ck-card flex items-start gap-4"
             :class="isDark ? 'border-violet-500/20 bg-violet-500/5' : 'border-violet-200 bg-violet-50'">
          <div class="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
               :class="isDark ? 'bg-violet-500/15' : 'bg-violet-100'">
            <AtomIcon class="w-5 h-5 text-violet-400" />
          </div>
          <div>
            <p class="text-sm font-bold mb-1" :class="isDark ? 'text-dark-text' : 'text-light-text'">
              FALCON — NTRU格紧凑签名算法
            </p>
            <p class="text-xs leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
              目前 Go 生态系统中尚无成熟的纯 Go FALCON 实现。该算法依赖高精度浮点运算，
              直接翻译为 Go 存在正确性风险，主流实现均为 C 参考代码。
            </p>
          </div>
        </div>

        <!-- 参数集信息 -->
        <div class="ck-card">
          <p class="ck-section-title">参数集规格</p>
          <div class="space-y-2">
            <div v-for="p in falconParamInfo" :key="p.name"
                 class="flex items-center justify-between p-2.5 rounded-xl border text-xs"
                 :class="isDark ? 'border-dark-border bg-dark-bg/50' : 'border-light-border bg-gray-50'">
              <span class="font-bold text-violet-400">{{ p.name }}</span>
              <div class="flex gap-3 text-right" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
                <span>公钥 <b class="text-cyan-400">{{ p.pk }}</b></span>
                <span>签名 <b class="text-amber-400">{{ p.sig }}</b></span>
                <span class="ck-badge-purple">{{ p.nist }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- 路线图 -->
        <div class="ck-card">
          <p class="ck-section-title">集成路线图</p>
          <div class="space-y-2 text-xs" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="flex gap-2 items-start">
              <span class="text-emerald-400 shrink-0 mt-0.5">✅</span>
              <span>ML-DSA (Dilithium) — 已上线，纯 Go，via cloudflare/circl</span>
            </div>
            <div class="flex gap-2 items-start">
              <span class="text-emerald-400 shrink-0 mt-0.5">✅</span>
              <span>SLH-DSA (SPHINCS+) — 已上线，纯 Go，via cloudflare/circl</span>
            </div>
            <div class="flex gap-2 items-start">
              <span class="text-amber-400 shrink-0 mt-0.5">🔄</span>
              <span>FALCON — 跟踪 <a href="#" class="text-violet-400 underline">filippo.io/mlkem768</a> 等纯 Go PQC 库进展，计划随官方库成熟后接入</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 右列: 算法原理 -->
      <div class="ck-card ck-right-panel">
        <p class="ck-section-title">算法原理 (FALCON)</p>
        <div class="text-xs space-y-3 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
          <div class="p-3 rounded-xl border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-2 text-violet-400">设计基础</p>
            <p>FALCON 基于 NTRU 格，采用 Gentry-Peikert-Vaikuntanathan (GPV) 框架的陷门高斯采样，使用 Fast Fourier Sampling over NTRU lattices 技术高效生成签名。</p>
          </div>
          <div class="p-3 rounded-xl border border-amber-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-2 text-amber-400">尺寸优势 — PQC 中最小签名</p>
            <p>FALCON-512 签名仅约 666B，公钥 897B，远小于 ML-DSA-44 (签名 2420B)。在带宽受限场景 (TLS、区块链) 中具有显著优势。</p>
          </div>
          <div class="p-3 rounded-xl border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-2 text-blue-400">NIST 标准化状态</p>
            <p>FALCON 已作为 NIST PQC 签名候选之一纳入评估 (FIPS 206 草案阶段)，与 ML-DSA 互补，ML-DSA 为主流推荐、FALCON 为紧凑场景备选。</p>
          </div>
          <div class="p-3 rounded-xl border border-red-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-2 text-red-400">实现挑战</p>
            <p>FALCON 中的高斯采样依赖 IEEE 754 双精度浮点的特定精度保证，正确的常数时间实现极其困难，官方参考实现为 C 语言，Go 移植尚在社区讨论阶段。</p>
          </div>
        </div>
      </div>
    </div>

    <!-- HQC — 调研预览 -->
    <div v-if="activeTab === 'hqc'" class="ck-workbench animate-fade-in">
      <!-- 左列 -->
      <div class="ck-stack">
        <!-- 状态横幅 -->
        <div class="ck-card flex items-start gap-4"
             :class="isDark ? 'border-emerald-500/20 bg-emerald-500/5' : 'border-emerald-200 bg-emerald-50'">
          <div class="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
               :class="isDark ? 'bg-emerald-500/15' : 'bg-emerald-100'">
            <AtomIcon class="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <p class="text-sm font-bold mb-1" :class="isDark ? 'text-dark-text' : 'text-light-text'">
              HQC — 准循环码密钥封装
            </p>
            <p class="text-xs leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
              HQC 目前处于 NIST PQC 第四轮候选阶段，Go 生态尚无稳定的纯 Go 实现。
              与 ML-KEM 的格密码路线不同，HQC 基于纠错码，是重要的算法多样性补充。
            </p>
          </div>
        </div>

        <!-- 参数对比 -->
        <div class="ck-card">
          <p class="ck-section-title">参数集规格</p>
          <div class="space-y-2">
            <div v-for="p in hqcParamInfo" :key="p.name"
                 class="flex items-center justify-between p-2.5 rounded-xl border text-xs"
                 :class="isDark ? 'border-dark-border bg-dark-bg/50' : 'border-light-border bg-gray-50'">
              <span class="font-bold text-emerald-400">{{ p.name }}</span>
              <div class="flex gap-3 text-right" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
                <span>公钥 <b class="text-cyan-400">{{ p.pk }}</b></span>
                <span>密文 <b class="text-amber-400">{{ p.ct }}</b></span>
                <span class="ck-badge-green">{{ p.nist }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- 与 ML-KEM 对比 -->
        <div class="ck-card">
          <p class="ck-section-title">HQC vs ML-KEM 对比</p>
          <div class="space-y-2 text-xs" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="grid grid-cols-3 gap-1 text-center text-[10px] font-bold pb-1 border-b"
                 :class="isDark ? 'border-dark-border text-dark-muted' : 'border-light-border text-light-muted'">
              <span>指标</span><span class="text-cyan-400">ML-KEM-768</span><span class="text-emerald-400">HQC-192</span>
            </div>
            <div v-for="row in hqcCompare" :key="row.label"
                 class="grid grid-cols-3 gap-1 text-center text-[11px]">
              <span>{{ row.label }}</span>
              <span :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ row.mlkem }}</span>
              <span :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ row.hqc }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 右列: 算法原理 -->
      <div class="ck-card ck-right-panel">
        <p class="ck-section-title">算法原理 (HQC)</p>
        <div class="text-xs space-y-3 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
          <div class="p-3 rounded-xl border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-2 text-emerald-400">设计基础</p>
            <p>HQC (Hamming Quasi-Cyclic) 基于准循环码上的解密失败概率难题。密钥是准循环 LDPC/LRPC 码，安全性归约到随机线性码上的解码问题。</p>
          </div>
          <div class="p-3 rounded-xl border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-2 text-blue-400">多样性价值</p>
            <p>HQC 与 ML-KEM 的安全假设完全不同 (纠错码 vs 格)。NIST 同时推进两类 KEM 标准，目的是防范单一数学问题被量子算法或经典算法突破的风险。</p>
          </div>
          <div class="p-3 rounded-xl border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-2 text-violet-400">NIST 标准化进展</p>
            <p>HQC 于 2024 年入选 NIST PQC 第四轮，预计 2025-2026 年完成标准化。届时将作为 ML-KEM 的备选 KEM 正式发布，可与 ML-KEM 混合部署以提升安全边界。</p>
          </div>
          <div class="p-3 rounded-xl border border-amber-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-2 text-amber-400">实现现状</p>
            <p>HQC 参考实现为 C 语言。Go 社区中目前没有经过审计的成熟实现，待 NIST 最终标准发布后，预计 Go 标准库或 cloudflare/circl 将跟进。</p>
          </div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { storeToRefs } from 'pinia'
import { AtomIcon, KeyIcon, LockIcon, UnlockIcon, PenIcon, CheckCircleIcon, XCircleIcon, CopyIcon, InfoIcon, XIcon } from 'lucide-vue-next'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import {
  MLKEMKeyGen, MLKEMEncapsulate, MLKEMDecapsulate,
  MLDSAKeyGen, MLDSASign, MLDSAVerify,
  SLHDSAKeyGen, SLHDSASign, SLHDSAVerify,
} from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'mlkem', label: 'ML-KEM (Kyber)' },
  { id: 'mldsa', label: 'ML-DSA (Dilithium)' },
  { id: 'slhdsa', label: 'SLH-DSA (SPHINCS+)' },
  { id: 'falcon', label: 'FALCON' },
  { id: 'hqc', label: 'HQC' },
]
const activeTab = ref('mlkem')

// Principles
const showPrinciple = ref(false)
const principles = {
  mlkem: {
    title: 'ML-KEM (FIPS 203) 算法原理',
    content: '基于格的密钥封装机制 (Lattice-based KEM)。\n- 前身：Kyber 算法。\n- 安全性：基于模学习误差难题 (Module-LWE)。\n- 优势：能够在量子计算机攻击下保持安全，且具有较小的密钥和密文尺寸。'
  },
  mldsa: {
    title: 'ML-DSA (FIPS 204) 算法原理',
    content: '基于格的数字签名算法 (Lattice-based DSA)。\n- 前身：Dilithium 算法。\n- 安全性：基于模学习误差 (MLWE) 和模短整数解 (MSIS) 难题。\n- 优势：签名和验证速度极快，是后量子时代数字签名的首选标准。'
  },
  slhdsa: {
    title: 'SLH-DSA (FIPS 205) 算法原理',
    content: '无状态哈希数字签名算法 (Stateless Hash-based DSA)。\n- 前身：SPHINCS+ 算法。\n- 安全性：仅基于哈希函数的抗碰撞性和抗原像性，不依赖格难题。\n- 优势：极高的安全性保障，即使基于格的算法被破解，SLH-DSA 依然安全。'
  },
  falcon: {
    title: 'FALCON 算法原理',
    content: '基于 NTRU 格的紧凑签名算法。\n- 特点：采用了 Fast Fourier Sampling (FFT) 技术。\n- 优势：签名尺寸在所有 PQC 算法中是最小的，适用于对带宽极度敏感的场景。'
  },
  hqc: {
    title: 'HQC 算法原理',
    content: '基于纠错码的密钥封装机制 (Hamming Quasi-Cyclic)。\n- 安全性：基于准循环码上的解错难题。\n- 优势：设计理念不同于格密码，提供了算法多样性保障。'
  }
}
const currentPrinciple = computed(() => principles[activeTab.value])

// ML-KEM
const kem = reactive({ paramSet: 'ML-KEM-768' })
const kemKeys = reactive({ privateKey: '', publicKey: '' })
const kemEncapResult = reactive({ ciphertext: '', sharedSecret: '' })
const kemDecapResult = reactive({ data: '', error: '' })

async function genKEMKey() {
  const r = await MLKEMKeyGen(kem.paramSet)
  if (r.success) { kemKeys.privateKey = r.privateKey; kemKeys.publicKey = r.publicKey }
}
async function kemEncap() {
  const r = await MLKEMEncapsulate({ publicKey: kemKeys.publicKey, paramSet: kem.paramSet })
  if (r.success) { kemEncapResult.ciphertext = r.ciphertext; kemEncapResult.sharedSecret = r.sharedSecret }
}
async function kemDecap() {
  const r = await MLKEMDecapsulate({ privateKey: kemKeys.privateKey, ciphertext: kemEncapResult.ciphertext, paramSet: kem.paramSet })
  kemDecapResult.data = r.data; kemDecapResult.error = r.error
}

// FALCON — 静态参数信息展示 (暂无纯 Go 实现，仅展示规格)
const falconParamInfo = [
  { name: 'Falcon-512',        pk: '897B',  sig: '~666B',  nist: 'NIST-1' },
  { name: 'Falcon-1024',       pk: '1793B', sig: '~1280B', nist: 'NIST-5' },
  { name: 'Falcon-padded-512', pk: '897B',  sig: '809B',   nist: 'NIST-1' },
]

// HQC — 静态参数信息展示
const hqcParamInfo = [
  { name: 'HQC-128', pk: '2249B',  ct: '4481B',  nist: 'NIST-1' },
  { name: 'HQC-192', pk: '4522B',  ct: '9026B',  nist: 'NIST-3' },
  { name: 'HQC-256', pk: '7245B',  ct: '14469B', nist: 'NIST-5' },
]
const hqcCompare = [
  { label: '公钥大小', mlkem: '1184B', hqc: '4522B'  },
  { label: '密文大小', mlkem: '1088B', hqc: '9026B'  },
  { label: '共享密钥', mlkem: '32B',   hqc: '64B'    },
  { label: '安全假设', mlkem: '格(LWE)', hqc: '纠错码' },
  { label: 'Go 支持',  mlkem: '✅ 已上线', hqc: '🔄 调研中' },
]

const kemParams = [
  { name: 'ML-KEM-512',  pubKey: '800B',  ct: '768B',  security: 'NIST-1' },
  { name: 'ML-KEM-768',  pubKey: '1184B', ct: '1088B', security: 'NIST-3' },
  { name: 'ML-KEM-1024', pubKey: '1568B', ct: '1568B', security: 'NIST-5' },
]

// ML-DSA
const dsa = reactive({ paramSet: 'ML-DSA-65', data: '' })
const dsaKeys = reactive({ privateKey: '', publicKey: '' })
const dsaResult = reactive({ data: '', error: '', success: null })

async function genDSAKey() {
  const r = await MLDSAKeyGen(dsa.paramSet)
  if (r.success) { dsaKeys.privateKey = r.privateKey; dsaKeys.publicKey = r.publicKey }
}
async function dsaSign() {
  const r = await MLDSASign({ privateKey: dsaKeys.privateKey, data: dsa.data, paramSet: dsa.paramSet })
  dsaResult.data = r.data; dsaResult.error = r.error; dsaResult.success = r.success
}
async function dsaVerify() {
  const r = await MLDSAVerify({ publicKey: dsaKeys.publicKey, data: dsa.data, signature: dsaResult.data, paramSet: dsa.paramSet })
  dsaResult.data = r.data; dsaResult.error = r.error; dsaResult.success = r.success
}

const dsaParams = [
  { name: 'ML-DSA-44', pubKey: '1312B', sig: '2420B', security: 'NIST-2' },
  { name: 'ML-DSA-65', pubKey: '1952B', sig: '3309B', security: 'NIST-3' },
  { name: 'ML-DSA-87', pubKey: '2592B', sig: '4627B', security: 'NIST-5' },
]

// SLH-DSA
const slh = reactive({ paramSet: 'SLH-DSA-SHA2-128s', data: '' })
const slhKeys = reactive({ privateKey: '', publicKey: '' })
const slhResult = reactive({ data: '', error: '', success: null })

async function genSLHKey() {
  const r = await SLHDSAKeyGen(slh.paramSet)
  if (r.success) { slhKeys.privateKey = r.privateKey; slhKeys.publicKey = r.publicKey }
}
async function slhSign() {
  const r = await SLHDSASign({ privateKey: slhKeys.privateKey, data: slh.data, paramSet: slh.paramSet })
  slhResult.data = r.data; slhResult.error = r.error; slhResult.success = r.success
}
async function slhVerify() {
  const r = await SLHDSAVerify({ publicKey: slhKeys.publicKey, data: slh.data, signature: slhResult.data, paramSet: slh.paramSet })
  slhResult.data = r.data; slhResult.error = r.error; slhResult.success = r.success
}

const slhParams = [
  { name: 'SLH-DSA-SHA2-128s',  pubKey: '32B', sig: '7856B',  security: 'NIST-1' },
  { name: 'SLH-DSA-SHA2-128f',  pubKey: '32B', sig: '17088B', security: 'NIST-1' },
  { name: 'SLH-DSA-SHAKE-128s', pubKey: '32B', sig: '7856B',  security: 'NIST-1' },
  { name: 'SLH-DSA-SHAKE-128f', pubKey: '32B', sig: '17088B', security: 'NIST-1' },
  { name: 'SLH-DSA-SHA2-192s',  pubKey: '48B', sig: '16224B', security: 'NIST-3' },
  { name: 'SLH-DSA-SHA2-192f',  pubKey: '48B', sig: '35664B', security: 'NIST-3' },
  { name: 'SLH-DSA-SHAKE-192s', pubKey: '48B', sig: '16224B', security: 'NIST-3' },
  { name: 'SLH-DSA-SHAKE-192f', pubKey: '48B', sig: '356644B', security: 'NIST-3' },
  { name: 'SLH-DSA-SHA2-256s',  pubKey: '64B', sig: '29792B', security: 'NIST-5' },
  { name: 'SLH-DSA-SHA2-256f',  pubKey: '64B', sig: '49856B', security: 'NIST-5' },
  { name: 'SLH-DSA-SHAKE-256s', pubKey: '64B', sig: '29792B', security: 'NIST-5' },
  { name: 'SLH-DSA-SHAKE-256f', pubKey: '64B', sig: '49856B', security: 'NIST-5' },
]

async function copy(text) {
  if (!text) return
  await navigator.clipboard.writeText(text)
  store.showToast('已复制')
}

function base64ByteLen(b64) {
  if (!b64) return 0
  try {
    return atob(b64).length
  } catch {
    return Math.ceil(b64.length * 0.75)
  }
}
</script>
