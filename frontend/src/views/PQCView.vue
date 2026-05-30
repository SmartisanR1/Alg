<template>
  <PageLayout title="后量子密码 (PQC)" subtitle="FIPS 203 ML-KEM · FIPS 204 ML-DSA · FIPS 205 SLH-DSA"
              icon-bg="bg-purple-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <AtomIcon class="w-4 h-4 text-purple-400" />
    </template>

    <template #actions>
      <Button variant="secondary" size="sm" @click="showPrinciple = true">
        <InfoIcon class="w-3.5 h-3.5" /> 算法原理
      </Button>
    </template>

    <!-- Principle Modal -->
    <transition name="fade">
      <div v-if="showPrinciple" class="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" @click.self="showPrinciple = false">
        <div class="card max-w-2xl w-full shadow-2xl animate-in zoom-in-95 duration-200 overflow-hidden flex flex-col max-h-[85vh]">
          <div class="flex justify-between items-center p-4 border-b shrink-0">
            <h3 class="text-sm font-bold flex items-center gap-2">
              <InfoIcon class="w-4 h-4 text-violet-400" /> {{ currentPrinciple.title }}
            </h3>
            <button @click="showPrinciple = false" class="p-1 hover:bg-gray-100 dark:hover:bg-dark-hover rounded-md transition-colors">
              <XIcon class="w-4 h-4 text-dark-muted" />
            </button>
          </div>
          <div class="flex-1 overflow-y-auto p-6 custom-scrollbar">
            <AlgorithmPrinciple
              :title="currentPrinciple.title"
              type="pqc"
              :sections="parsedPrinciples"
            />
          </div>
          <div class="p-4 border-t shrink-0 flex justify-end bg-gray-50/50 dark:bg-dark-bg/20">
            <Button variant="primary" @click="showPrinciple = false">确认并返回</Button>
          </div>
        </div>
      </div>
    </transition>

    <!-- ML-KEM -->
    <div v-if="activeTab === 'mlkem'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <Card>
          <div class="flex items-center gap-2 mb-3">
            <span class="badge">FIPS 203</span>
            <p class="text-sm font-medium">ML-KEM (Kyber) — 密钥封装机制</p>
          </div>
          <div>
            <label class="input-label">参数集</label>
            <Dropdown
              v-model="kem.paramSet"
              :options="[
                { value: 'ML-KEM-512', label: 'ML-KEM-512 (128位安全)' },
                { value: 'ML-KEM-768', label: 'ML-KEM-768 (192位安全)' },
                { value: 'ML-KEM-1024', label: 'ML-KEM-1024 (256位安全)' }
              ]"
              class="mb-3"
            />
          </div>
          <Button variant="secondary" block @click="genKEMKey" class="mb-3">
            <KeyIcon class="w-3.5 h-3.5" /> 生成密钥对
          </Button>
          <div v-if="kemKeys.publicKey" class="space-y-2 flex-1 min-h-0 flex flex-col">
            <div class="flex-1 min-h-0 flex flex-col">
              <div class="flex justify-between mb-1 shrink-0">
                <label class="input-label !mb-0 text-amber-200">私钥 (Private Key)</label>
                <Button variant="tool" size="sm" @click="copy(kemKeys.privateKey)"><CopyIcon class="w-3 h-3" /></Button>
              </div>
              <textarea readonly class="result-area ck-key-hex !min-h-[96px] text-amber-200 text-[12px] font-mono w-full flex-1 resize-none bg-transparent outline-none border-none overflow-y-auto" :value="kemKeys.privateKey"></textarea>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-200 border-amber-400/30 bg-amber-400/10">
                  {{ base64ByteLen(kemKeys.privateKey) + ' bytes' }}
                </span>
              </div>
            </div>
            <div class="flex-1 min-h-0 flex flex-col mt-2">
              <div class="flex justify-between mb-1 shrink-0">
                <label class="input-label !mb-0 text-cyan-400">公钥 (Public Key)</label>
                <Button variant="tool" size="sm" @click="copy(kemKeys.publicKey)"><CopyIcon class="w-3 h-3" /></Button>
              </div>
              <textarea readonly class="result-area ck-key-hex !min-h-[96px] text-cyan-200 text-[12px] font-mono w-full flex-1 resize-none bg-transparent outline-none border-none overflow-y-auto" :value="kemKeys.publicKey"></textarea>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-cyan-400 border-cyan-500/20 bg-cyan-500/5">
                  {{ base64ByteLen(kemKeys.publicKey) + ' bytes' }}
                </span>
              </div>
            </div>
          </div>
        </Card>
      </div>

      <div class="space-y-3 sym-main">
        <Card title="封装/解封装" class="space-y-3">
          <Button variant="success" block @click="kemEncap" :disabled="!kemKeys.publicKey">
            <LockIcon class="w-3.5 h-3.5" /> 封装 (Encapsulate)
          </Button>
          <div v-if="kemEncapResult.ciphertext" class="space-y-2">
            <div>
              <label class="input-label text-emerald-400">密文 (Ciphertext)</label>
              <div class="result-area text-emerald-300 text-[12px]">{{ kemEncapResult.ciphertext?.slice(0,80) }}...</div>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="input-label !mb-0 text-yellow-200">共享密钥 (Shared Secret)</label>
                <Button variant="tool" size="sm" @click="copy(kemEncapResult.sharedSecret)"><CopyIcon class="w-3 h-3" /></Button>
              </div>
              <div class="result-area text-yellow-200 font-mono">{{ kemEncapResult.sharedSecret }}</div>
            </div>
          </div>
        </Card>

        <Card title="解封装" class="space-y-3">
          <Button variant="warning" block @click="kemDecap" :disabled="!kemKeys.privateKey || !kemEncapResult.ciphertext">
            <UnlockIcon class="w-3.5 h-3.5" /> 解封装 (Decapsulate)
          </Button>
          <div v-if="kemDecapResult.data">
            <div class="flex justify-between mb-1">
              <label class="input-label !mb-0 text-yellow-200">恢复的共享密钥</label>
              <Button variant="tool" size="sm" @click="copy(kemDecapResult.data)"><CopyIcon class="w-3 h-3" /></Button>
            </div>
            <div class="result-area text-yellow-200 font-mono">{{ kemDecapResult.data }}</div>
            <div class="mt-2 text-xs flex items-center gap-1"
                 :class="kemEncapResult.sharedSecret === kemDecapResult.data ? 'text-emerald-400' : 'text-red-400'">
              <CheckCircleIcon v-if="kemEncapResult.sharedSecret === kemDecapResult.data" class="w-3.5 h-3.5" />
              <XCircleIcon v-else class="w-3.5 h-3.5" />
              {{ kemEncapResult.sharedSecret === kemDecapResult.data ? '✅ 共享密钥一致！密钥交换成功' : '❌ 共享密钥不匹配' }}
            </div>
          </div>
        </Card>

        <Card title="参数对比">
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
        </Card>
      </div>
    </div>

    <!-- ML-DSA -->
    <div v-if="activeTab === 'mldsa'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <div class="card">
          <div class="flex items-center gap-2 mb-3">
            <span class="badge">FIPS 204</span>
            <p class="text-sm font-medium">ML-DSA (Dilithium) — 数字签名</p>
          </div>
          <label class="input-label">参数集</label>
          <Dropdown
            v-model="dsa.paramSet"
            :options="[
              { value: 'ML-DSA-44', label: 'ML-DSA-44 (128位安全)' },
              { value: 'ML-DSA-65', label: 'ML-DSA-65 (192位安全)' },
              { value: 'ML-DSA-87', label: 'ML-DSA-87 (256位安全)' }
            ]"
            class="mb-3"
          />
          <button @click="genDSAKey" class="btn-secondary w-full justify-center mb-3">
            <KeyIcon class="w-3.5 h-3.5" /> 生成签名密钥对
          </button>
          <div v-if="dsaKeys.publicKey" class="space-y-2 flex-1 min-h-0 flex flex-col">
            <div class="flex-1 min-h-0 flex flex-col">
              <label class="input-label text-amber-200 shrink-0">私钥 (Private Key)</label>
              <textarea readonly class="result-area ck-key-hex !min-h-[96px] text-amber-200 text-[12px] font-mono w-full flex-1 resize-none bg-transparent outline-none border-none overflow-y-auto" :value="dsaKeys.privateKey"></textarea>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-200 border-amber-400/30 bg-amber-400/10">
                  {{ base64ByteLen(dsaKeys.privateKey) + ' bytes' }}
                </span>
              </div>
            </div>
            <div class="flex-1 min-h-0 flex flex-col mt-2">
              <label class="input-label text-cyan-400 shrink-0">公钥 (Public Key)</label>
              <textarea readonly class="result-area ck-key-hex !min-h-[96px] text-cyan-200 text-[12px] font-mono w-full flex-1 resize-none bg-transparent outline-none border-none overflow-y-auto" :value="dsaKeys.publicKey"></textarea>
              <div class="flex gap-3 mt-1">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-cyan-400 border-cyan-500/20 bg-cyan-500/5">
                  {{ base64ByteLen(dsaKeys.publicKey) + ' bytes' }}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div class="card">
          <CryptoPanel v-model="dsa.data" label="待签名数据 (hex)" type="textarea" :rows="3" clearable />
        </div>
      </div>

      <div class="space-y-3 sym-main">
        <div class="flex gap-2">
          <button @click="dsaSign" :disabled="!dsaKeys.privateKey" class="btn-success flex-1 justify-center">
            <PenIcon class="w-3.5 h-3.5" /> 签名
          </button>
          <button @click="dsaVerify" :disabled="!dsaKeys.publicKey || !dsaResult.data"
                  class="btn-warning flex-1 justify-center">
            <CheckCircleIcon class="w-3.5 h-3.5" /> 验签
          </button>
        </div>
        <div class="card">
          <CryptoPanel v-model="dsaResult.data" label="签名 (hex, 截断显示)" type="result"
                       :success="dsaResult.success" copyable />
          <div v-if="dsaResult.error" class="mt-2 text-xs"
               :class="dsaResult.data === 'true' ? 'text-emerald-400' : 'text-red-400'">
            {{ dsaResult.error || (dsaResult.data === 'true' ? '✅ 签名验证通过' : '') }}
          </div>
        </div>
        <div class="card">
          <p class="card-title">参数对比</p>
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
    <div v-if="activeTab === 'slhdsa'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <div class="card">
          <div class="flex items-center gap-2 mb-3">
            <span class="badge">FIPS 205</span>
            <p class="text-sm font-medium">SLH-DSA (SPHINCS+) — 无状态签名</p>
          </div>
          <div class="flex gap-2 items-end mb-3">
            <div class="flex-1">
              <label class="input-label">参数集选择</label>
              <Dropdown
                v-model="slh.paramSet"
                :options="slhParams.map(p => ({ value: p.name, label: p.name + ' (' + p.security + ')' }))"
              />
            </div>
            <button @click="genSLHKey" class="btn-secondary px-6 py-2">
              <KeyIcon class="w-3.5 h-3.5" /> 生成密钥
            </button>
          </div>
          
          <div v-if="slhKeys.publicKey" class="space-y-3 animate-in fade-in duration-300">
            <div>
              <div class="flex justify-between mb-1">
                <label class="input-label !mb-0 text-amber-200">私钥 (Private Key)</label>
                <button @click="copy(slhKeys.privateKey)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /> 复制</button>
              </div>
              <div class="result-area !min-h-[42px] !max-h-[60px] text-amber-200 text-[12px] font-mono leading-tight bg-amber-400/10 border-amber-400/20">
                {{ slhKeys.privateKey }}
              </div>
              <div class="mt-1 text-[9px] opacity-40 font-mono">Size: {{ base64ByteLen(slhKeys.privateKey) }} bytes</div>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="input-label !mb-0 text-cyan-400">公钥 (Public Key)</label>
                <button @click="copy(slhKeys.publicKey)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /> 复制</button>
              </div>
              <div class="result-area !min-h-[42px] !max-h-[60px] text-cyan-200 text-[12px] font-mono leading-tight bg-cyan-500/5 border-cyan-500/10">
                {{ slhKeys.publicKey }}
              </div>
              <div class="mt-1 text-[9px] opacity-40 font-mono">Size: {{ base64ByteLen(slhKeys.publicKey) }} bytes</div>
            </div>
          </div>
          <div v-else class="py-10 flex flex-col items-center justify-center text-dark-muted opacity-30 border-2 border-dashed border-dark-border rounded-xl">
             <KeyIcon class="w-8 h-8 mb-2" />
             <p class="text-[11px]">SLH-DSA 密钥尺寸极小 (通常 32-64B)</p>
          </div>
        </div>
        <div class="card">
          <CryptoPanel v-model="slh.data" label="待签名数据 (Hex)" type="textarea" :rows="2" clearable />
        </div>
      </div>

      <div class="sym-main">
        <div class="flex gap-2">
          <button @click="slhSign" :disabled="!slhKeys.privateKey" class="btn-success flex-1 justify-center py-2">
            <PenIcon class="w-3.5 h-3.5" /> 签名
          </button>
          <button @click="slhVerify" :disabled="!slhKeys.publicKey || !slhResult.data"
                  class="btn-warning flex-1 justify-center py-2">
            <CheckCircleIcon class="w-3.5 h-3.5" /> 验签
          </button>
        </div>
        <div class="card">
          <CryptoPanel v-model="slhResult.data" label="签名结果 (截断显示)" type="result"
                       :success="slhResult.success" copyable />
          <div v-if="slhResult.error || slhResult.success !== null" class="mt-2 text-[11px] font-bold"
               :class="slhResult.success ? 'text-emerald-400' : 'text-red-400'">
            {{ slhResult.error || (slhResult.success ? '✅ 签名验证通过' : '❌ 签名验证失败') }}
          </div>
        </div>
        <div class="card bg-gradient-to-br from-emerald-500/5 to-transparent border-emerald-500/10">
          <p class="card-title text-emerald-400">算法特性 (SLH-DSA)</p>
          <div class="text-[11px] space-y-2 leading-relaxed opacity-80">
            <p>• <b>安全性:</b> 仅依赖哈希函数的抗碰撞性，极其稳健。</p>
            <p>• <b>尺寸:</b> 公私钥极小，但签名尺寸较大 (KB级别)。</p>
            <p>• <b>应用:</b> 适用于根证书签名、固件签名等对安全性要求极高但签名频率较低的场景。</p>
          </div>
        </div>
      </div>
    </div>

    <!-- FALCON — 调研预览 -->
    <div v-if="activeTab === 'falcon'" class="sym-workbench animate-fade-in">
      <!-- 左列: 算法说明 + 参数预览 -->
      <div class="sym-side">
        <!-- 状态横幅 -->
        <div class="card flex items-start gap-4"
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
              circl v1.6.3 不包含 FALCON 实现。Go 社区也没有成熟的纯 Go 方案。需等待 FIPS 206 标准正式发布后 circl 跟进。目前只能使用 ML-DSA 作为签名方案。
            </p>
          </div>
        </div>

        <div class="card flex flex-col items-center justify-center py-12 text-dark-muted space-y-3 opacity-60 border-dashed">
          <div class="w-12 h-12 rounded-full bg-violet-500/10 flex items-center justify-center">
            <SettingsIcon class="w-6 h-6 text-violet-400 animate-spin-slow" />
          </div>
          <p class="text-xs">正在适配 FIPS 206 标准 API...</p>
        </div>
      </div>

      <!-- 右列: 算法原理 -->
      <div class="card sym-main">
        <p class="card-title">算法原理 (FALCON)</p>
        <div class="text-xs space-y-3 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
          <div class="p-3 rounded-xl border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-2 text-violet-400">设计基础</p>
            <p>FALCON 基于 NTRU 格，采用 Gentry-Peikert-Vaikuntanathan (GPV) 框架的陷门高斯采样，使用 Fast Fourier Sampling over NTRU lattices 技术高效生成签名。</p>
          </div>
          <div class="p-3 rounded-xl border border-amber-400/20" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-2 text-amber-200">尺寸优势 — PQC 中最小签名</p>
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
    <div v-if="activeTab === 'hqc'" class="sym-workbench animate-fade-in">
      <!-- 左列 -->
      <div class="sym-side">
        <!-- 状态横幅 -->
        <div class="card flex items-start gap-4"
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
              HQC 已入选 NIST 第四轮。目前 Go 仅有基于 CGO 的 liboqs 绑定，纯 Go 实现尚在开发中。本工具优先保证跨平台无依赖，待稳定实现发布后即刻上线。
            </p>
          </div>
        </div>

        <div class="card flex flex-col items-center justify-center py-12 text-dark-muted space-y-3 opacity-60 border-dashed">
          <div class="w-12 h-12 rounded-full bg-emerald-500/10 flex items-center justify-center">
            <SettingsIcon class="w-6 h-6 text-emerald-400 animate-spin-slow" />
          </div>
          <p class="text-xs">等待 NIST 标准化及稳定 Go 实现...</p>
        </div>
      </div>

      <!-- 右列: 算法原理 -->
      <div class="card sym-main">
        <p class="card-title">算法原理 (HQC)</p>
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
          <div class="p-3 rounded-xl border border-amber-400/20" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-2 text-amber-200">实现现状</p>
            <p>HQC 参考实现为 C 语言。Go 社区中目前没有经过审计的成熟实现，待 NIST 最终标准发布后，预计 Go 标准库或 cloudflare/circl 将跟进。</p>
          </div>
        </div>
      </div>
    </div>

    <!-- X-Wing -->
    <div v-if="activeTab === 'xwing'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <div class="card">
          <div class="flex items-center gap-2 mb-3">
            <span class="badge">Hybrid</span>
            <p class="text-sm font-medium">X-Wing — PQ/T 混合 KEM</p>
          </div>
          <button @click="genXWingKey" class="btn-secondary w-full justify-center mb-3">
            <KeyIcon class="w-3.5 h-3.5" /> 生成 X-Wing 密钥对
          </button>
          <div v-if="xwingKeys.publicKey" class="space-y-2">
            <div>
              <div class="flex justify-between mb-1">
                <label class="input-label !mb-0 text-amber-200">私钥</label>
                <button @click="copy(xwingKeys.privateKey)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <textarea readonly class="result-area ck-key-hex !min-h-[64px] text-amber-200 text-[12px] font-mono w-full resize-none bg-transparent outline-none border-none" :value="xwingKeys.privateKey"></textarea>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="input-label !mb-0 text-cyan-400">公钥 (1216B = ML-KEM-768 + X25519)</label>
                <button @click="copy(xwingKeys.publicKey)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <textarea readonly class="result-area ck-key-hex !min-h-[64px] text-cyan-200 text-[12px] font-mono w-full resize-none bg-transparent outline-none border-none" :value="xwingKeys.publicKey"></textarea>
            </div>
          </div>
        </div>
        <div class="card space-y-2">
          <button @click="xwingEncap" class="btn-success w-full justify-center"><LockIcon class="w-3.5 h-3.5" /> 封装 (Encapsulate)</button>
          <div v-if="xwingEncapResult.ciphertext" class="space-y-2 animate-in fade-in">
            <div>
              <label class="input-label text-emerald-400">密文</label>
              <textarea readonly class="result-area ck-key-hex !min-h-[48px] text-emerald-300 text-[12px] font-mono w-full resize-none bg-transparent outline-none border-none" :value="xwingEncapResult.ciphertext"></textarea>
            </div>
            <div>
              <label class="input-label text-violet-400">共享密钥</label>
              <div class="result-area ck-key-hex !min-h-0 text-violet-300 text-[12px] font-mono break-all">{{ xwingEncapResult.sharedSecret }}</div>
            </div>
            <button @click="xwingDecap" class="btn-warning w-full justify-center"><UnlockIcon class="w-3.5 h-3.5" /> 解封装 (Decapsulate)</button>
            <div v-if="xwingDecapResult.data || xwingDecapResult.error" class="animate-in fade-in">
              <label class="input-label" :class="xwingDecapResult.error ? 'text-red-400' : 'text-emerald-400'">解封装结果</label>
              <div class="result-area ck-key-hex !min-h-0 text-[12px] font-mono break-all"
                   :class="xwingDecapResult.error ? 'text-red-400' : 'text-emerald-400'">
                {{ xwingDecapResult.error || xwingDecapResult.data }}
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="card sym-main">
        <p class="card-title">X-Wing 混合 KEM 原理</p>
        <div class="text-xs space-y-3 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
          <div class="p-3 rounded-xl border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-2 text-violet-400">设计思想</p>
            <p>X-Wing 将后量子 ML-KEM-768 与经典 X25519 组合。即使 ML-KEM 被破解，仍有 X25519 的经典安全保障。</p>
          </div>
          <div class="p-3 rounded-xl border border-cyan-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-2 text-cyan-400">密钥结构</p>
            <p>• 公钥 = ML-KEM-768 公钥 (1184B) || X25519 公钥 (32B) = 1216B</p>
            <p>• 私钥 = 种子 (32B)，内部派生两个子密钥</p>
          </div>
          <div class="p-3 rounded-xl border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
            <p class="font-bold mb-2 text-emerald-400">标准化</p>
            <p>IETF draft-connolly-cfrg-xwing-kem-05，基于 HPKE 的混合加密框架。</p>
          </div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { storeToRefs } from 'pinia'
import { AtomIcon, KeyIcon, LockIcon, UnlockIcon, PenIcon, CheckCircleIcon, XCircleIcon, CopyIcon, InfoIcon, XIcon, SettingsIcon } from 'lucide-vue-next'
import Card from '../components/Card.vue'
import Input from '../components/Input.vue'
import Button from '../components/Button.vue'
import ResultArea from '../components/ResultArea.vue'
import AlgorithmPrinciple from '../components/AlgorithmPrinciple.vue'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import Dropdown from '../components/Dropdown.vue'
import {
  MLKEMKeyGen, MLKEMEncapsulate, MLKEMDecapsulate,
  MLDSAKeyGen, MLDSASign, MLDSAVerify,
  SLHDSAKeyGen, SLHDSASign, SLHDSAVerify,
  XWingKeyGen, XWingEncapsulate, XWingDecapsulate,
} from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'mlkem', label: 'ML-KEM (Kyber)' },
  { id: 'mldsa', label: 'ML-DSA (Dilithium)' },
  { id: 'slhdsa', label: 'SLH-DSA (SPHINCS+)' },
  { id: 'xwing', label: 'X-Wing' },
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
  },
  xwing: {
    title: 'X-Wing 混合 KEM 原理',
    content: 'X-Wing 是 PQ/T 混合密钥封装机制，结合 ML-KEM-768 和 X25519。\n- 设计目标：即使 ML-KEM 被破解，仍有 X25519 的经典安全性保障。\n- 公钥 = ML-KEM-768 公钥 || X25519 公钥 (共 1184+32=1216 字节)\n- 适用于需要最高安全保障的过渡期场景。'
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

// X-Wing
const xwingKeys = reactive({ privateKey: '', publicKey: '' })
const xwingEncapResult = reactive({ ciphertext: '', sharedSecret: '' })
const xwingDecapResult = reactive({ data: '', error: '' })

async function genXWingKey() {
  const r = await XWingKeyGen()
  if (r.success) { xwingKeys.privateKey = r.privateKey; xwingKeys.publicKey = r.publicKey }
}
async function xwingEncap() {
  const r = await XWingEncapsulate({ publicKey: xwingKeys.publicKey })
  if (r.success) { xwingEncapResult.ciphertext = r.ciphertext; xwingEncapResult.sharedSecret = r.sharedSecret }
}
async function xwingDecap() {
  const r = await XWingDecapsulate({ privateKey: xwingKeys.privateKey, ciphertext: xwingEncapResult.ciphertext })
  xwingDecapResult.data = r.data; xwingDecapResult.error = r.error
}

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
