<template>
  <PageLayout title="后量子密码 (PQC)" subtitle="FIPS 203 ML-KEM · FIPS 204 ML-DSA · FIPS 205 SLH-DSA · TLS 1.3 混合交换"
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
                <label class="input-label !mb-0 text-orange-300">私钥 (Private Key)</label>
                <Button variant="tool" size="sm" @click="copy(kemKeys.privateKey)"><CopyIcon class="w-3 h-3" /></Button>
              </div>
              <div class="relative flex-1">
                <textarea readonly class="result-area ck-key-hex !min-h-[96px] text-orange-300 text-[12px] font-mono w-full h-full resize-none bg-transparent outline-none border-none overflow-y-auto pb-7" :value="kemKeys.privateKey"></textarea>
                <span class="bytes-badge-inside">
                  {{ base64ByteLen(kemKeys.privateKey) + ' bytes' }}
                </span>
              </div>
            </div>
            <div class="flex-1 min-h-0 flex flex-col mt-2">
              <div class="flex justify-between mb-1 shrink-0">
                <label class="input-label !mb-0 text-cyan-400">公钥 (Public Key)</label>
                <Button variant="tool" size="sm" @click="copy(kemKeys.publicKey)"><CopyIcon class="w-3 h-3" /></Button>
              </div>
              <div class="relative flex-1">
                <textarea readonly class="result-area ck-key-hex !min-h-[96px] text-cyan-300 text-[12px] font-mono w-full h-full resize-none bg-transparent outline-none border-none overflow-y-auto pb-7" :value="kemKeys.publicKey"></textarea>
                <span class="bytes-badge-inside">
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
              <div class="relative">
                <div class="result-area pb-7 text-emerald-300 text-[12px]">{{ kemEncapResult.ciphertext?.slice(0,80) }}...</div>
                <ByteBadge :model-value="kemEncapResult.ciphertext" />
              </div>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="input-label !mb-0 text-yellow-300">共享密钥 (Shared Secret)</label>
                <Button variant="tool" size="sm" @click="copy(kemEncapResult.sharedSecret)"><CopyIcon class="w-3 h-3" /></Button>
              </div>
              <div class="relative">
                <div class="result-area pb-7 text-yellow-300 font-mono">{{ kemEncapResult.sharedSecret }}</div>
                <ByteBadge :model-value="kemEncapResult.sharedSecret" />
              </div>
            </div>
          </div>
        </Card>

        <Card title="解封装" class="space-y-3">
          <Button variant="warning" block @click="kemDecap" :disabled="!kemKeys.privateKey || !kemEncapResult.ciphertext">
            <UnlockIcon class="w-3.5 h-3.5" /> 解封装 (Decapsulate)
          </Button>
          <div v-if="kemDecapResult.data">
            <div class="flex justify-between mb-1">
              <label class="input-label !mb-0 text-yellow-300">恢复的共享密钥</label>
              <Button variant="tool" size="sm" @click="copy(kemDecapResult.data)"><CopyIcon class="w-3 h-3" /></Button>
            </div>
            <div class="relative">
              <div class="result-area pb-7 text-yellow-300 font-mono">{{ kemDecapResult.data }}</div>
              <ByteBadge :model-value="kemDecapResult.data" />
            </div>
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
              <label class="input-label text-orange-300 shrink-0">私钥 (Private Key)</label>
              <div class="relative flex-1">
                <textarea readonly class="result-area ck-key-hex !min-h-[96px] text-orange-300 text-[12px] font-mono w-full h-full resize-none bg-transparent outline-none border-none overflow-y-auto pb-7" :value="dsaKeys.privateKey"></textarea>
                <span class="bytes-badge-inside">
                  {{ base64ByteLen(dsaKeys.privateKey) + ' bytes' }}
                </span>
              </div>
            </div>
            <div class="flex-1 min-h-0 flex flex-col mt-2">
              <label class="input-label text-cyan-400 shrink-0">公钥 (Public Key)</label>
              <div class="relative flex-1">
                <textarea readonly class="result-area ck-key-hex !min-h-[96px] text-cyan-300 text-[12px] font-mono w-full h-full resize-none bg-transparent outline-none border-none overflow-y-auto pb-7" :value="dsaKeys.publicKey"></textarea>
                <span class="bytes-badge-inside">
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
          <CryptoPanel v-model="dsaResult.data" label="签名 (HEX)" type="result"
                       :success="dsaResult.success" copyable :group-hex="false" class="break-all text-[11px]" />
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
                <label class="input-label !mb-0 text-orange-300">私钥 (Private Key)</label>
                <button @click="copy(slhKeys.privateKey)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /> 复制</button>
              </div>
              <div class="relative">
                <div class="result-area !min-h-[42px] !max-h-[60px] text-orange-300 text-[12px] font-mono leading-tight bg-orange-400/15 border-amber-400/20 pb-7">
                  {{ slhKeys.privateKey }}
                </div>
                <span class="bytes-badge-inside">
                  {{ base64ByteLen(slhKeys.privateKey) + ' bytes' }}
                </span>
              </div>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="input-label !mb-0 text-cyan-400">公钥 (Public Key)</label>
                <button @click="copy(slhKeys.publicKey)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /> 复制</button>
              </div>
              <div class="relative">
                <div class="result-area !min-h-[42px] !max-h-[60px] text-cyan-300 text-[12px] font-mono leading-tight bg-cyan-500/5 border-cyan-500/10 pb-7">
                  {{ slhKeys.publicKey }}
                </div>
                <span class="bytes-badge-inside">
                  {{ base64ByteLen(slhKeys.publicKey) + ' bytes' }}
                </span>
              </div>
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
                       :success="slhResult.success" copyable :group-hex="false" />
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

    <!-- AIGIS-sig -->
    <div v-if="activeTab === 'aigis'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <div class="card">
          <div class="flex items-center gap-2 mb-3">
            <span class="badge bg-amber-500/20 text-amber-400">国密 PQC</span>
            <p class="text-sm font-medium">AIGIS-sig — 国密格签名算法</p>
          </div>
          <label class="input-label">参数集</label>
          <Dropdown
            v-model="aigis.paramSet"
            :options="[
              { value: 'AIGIS-sig-1', label: 'AIGIS-sig-1' },
              { value: 'AIGIS-sig-2', label: 'AIGIS-sig-2' },
              { value: 'AIGIS-sig-3', label: 'AIGIS-sig-3' }
            ]"
            class="mb-3"
          />
          <button @click="genAigisKey" class="btn-secondary w-full justify-center mb-3">
            <KeyIcon class="w-3.5 h-3.5" /> 生成签名密钥对
          </button>
          <div v-if="aigisKeyError.error && !aigisKeys.publicKey" class="p-3 rounded-xl border border-red-500/20 bg-red-500/5 text-red-400 text-xs mb-3">
            {{ aigisKeyError.error }}
          </div>
          <div v-if="aigisKeys.publicKey" class="space-y-2 flex-1 min-h-0 flex flex-col">
            <div class="flex-1 min-h-0 flex flex-col">
              <label class="input-label text-orange-300 shrink-0">私钥 (Private Key)</label>
              <div class="relative flex-1">
                <textarea readonly class="result-area ck-key-hex !min-h-[96px] text-orange-300 text-[12px] font-mono w-full h-full resize-none bg-transparent outline-none border-none overflow-y-auto pb-7" :value="aigisKeys.privateKey"></textarea>
                <span class="bytes-badge-inside">
                  {{ base64ByteLen(aigisKeys.privateKey) + ' bytes' }}
                </span>
              </div>
            </div>
            <div class="flex-1 min-h-0 flex flex-col mt-2">
              <label class="input-label text-cyan-400 shrink-0">公钥 (Public Key)</label>
              <div class="relative flex-1">
                <textarea readonly class="result-area ck-key-hex !min-h-[96px] text-cyan-300 text-[12px] font-mono w-full h-full resize-none bg-transparent outline-none border-none overflow-y-auto pb-7" :value="aigisKeys.publicKey"></textarea>
                <span class="bytes-badge-inside">
                  {{ base64ByteLen(aigisKeys.publicKey) + ' bytes' }}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div class="card">
          <CryptoPanel v-model="aigis.data" label="待签名数据 (hex)" type="textarea" :rows="3" clearable />
        </div>
      </div>

      <div class="space-y-3 sym-main">
        <div class="flex gap-2">
          <button @click="aigisSign" :disabled="!aigisKeys.privateKey" class="btn-success flex-1 justify-center">
            <PenIcon class="w-3.5 h-3.5" /> 签名
          </button>
          <button @click="aigisVerify" :disabled="!aigisKeys.publicKey || !aigisResult.data"
                  class="btn-warning flex-1 justify-center">
            <CheckCircleIcon class="w-3.5 h-3.5" /> 验签
          </button>
        </div>
        <div class="card">
          <CryptoPanel v-model="aigisResult.data" label="签名 (HEX)" type="result"
                       :success="aigisResult.success" copyable :group-hex="false" class="break-all text-[11px]" />
          <div v-if="aigisResult.error" class="mt-2 text-xs"
               :class="aigisResult.data === 'true' ? 'text-emerald-400' : 'text-red-400'">
            {{ aigisResult.error || (aigisResult.data === 'true' ? '✅ 签名验证通过' : '') }}
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
              <tr class="border-t" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <td class="py-1 font-mono">AIGIS-sig-1</td>
                <td class="text-right">1056B</td>
                <td class="text-right">1852B</td>
                <td class="text-right">Level 1</td>
              </tr>
              <tr class="border-t" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <td class="py-1 font-mono">AIGIS-sig-2</td>
                <td class="text-right">1312B</td>
                <td class="text-right">2445B</td>
                <td class="text-right">Level 2</td>
              </tr>
              <tr class="border-t" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <td class="py-1 font-mono">AIGIS-sig-3</td>
                <td class="text-right">1568B</td>
                <td class="text-right">3046B</td>
                <td class="text-right">Level 3</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="card bg-gradient-to-br from-amber-500/5 to-transparent border-amber-500/10">
          <p class="card-title text-amber-400">算法说明</p>
          <div class="text-[11px] space-y-2 leading-relaxed opacity-80">
            <p>• <b>来源:</b> 中国科学院信息工程研究所设计，参加国密 PQC 算法征集。</p>
            <p>• <b>基础:</b> 基于 MLWE/MSIS 格难题，独立参数集，支持 SM3/SHAKE 双哈希模式。</p>
            <p>• <b>状态:</b> 按官方 PQMagic 参考实现完整移植，密钥生成/签名/验签全部可用，已通过官方测试向量验证。</p>
          </div>
        </div>
      </div>
    </div>

    <!-- FALCON -->
    <div v-if="activeTab === 'falcon'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <div class="card">
          <div class="flex items-center gap-2 mb-3">
            <span class="badge">FIPS 206</span>
            <p class="text-sm font-medium">FALCON / FN-DSA — 紧凑数字签名</p>
          </div>
          <label class="input-label">参数集</label>
          <Dropdown
            v-model="falcon.paramSet"
            :options="falconParamInfo.map(p => ({ value: p.name, label: p.name + ' (' + p.nist + ')' }))"
            class="mb-3"
          />
          <button @click="genFalconKey" class="btn-secondary w-full justify-center mb-3">
            <KeyIcon class="w-3.5 h-3.5" /> 生成签名密钥对
          </button>
          <div v-if="falconKeys.publicKey" class="space-y-2">
            <div>
              <div class="flex justify-between mb-1">
                <label class="input-label !mb-0 text-orange-300">私钥</label>
                <button @click="copy(falconKeys.privateKey)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="relative">
                <textarea readonly class="result-area ck-key-hex !min-h-[72px] text-orange-300 text-[12px] font-mono w-full resize-none bg-transparent outline-none border-none overflow-y-auto pb-7" :value="falconKeys.privateKey"></textarea>
                <span class="bytes-badge-inside">
                  {{ base64ByteLen(falconKeys.privateKey) + ' bytes' }}
                </span>
              </div>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="input-label !mb-0 text-cyan-400">公钥</label>
                <button @click="copy(falconKeys.publicKey)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="relative">
                <textarea readonly class="result-area ck-key-hex !min-h-[72px] text-cyan-300 text-[12px] font-mono w-full resize-none bg-transparent outline-none border-none overflow-y-auto pb-7" :value="falconKeys.publicKey"></textarea>
                <span class="bytes-badge-inside">
                  {{ base64ByteLen(falconKeys.publicKey) + ' bytes' }}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div class="card">
          <CryptoPanel v-model="falcon.data" label="待签名数据 (hex)" type="textarea" :rows="3" clearable />
        </div>
      </div>

      <div class="sym-main">
        <div class="flex gap-2">
          <button @click="falconSign" :disabled="!falconKeys.privateKey" class="btn-success flex-1 justify-center">
            <PenIcon class="w-3.5 h-3.5" /> 签名
          </button>
          <button @click="falconVerify" :disabled="!falconKeys.publicKey || !falconResult.data"
                  class="btn-warning flex-1 justify-center">
            <CheckCircleIcon class="w-3.5 h-3.5" /> 验签
          </button>
        </div>
        <div class="card">
          <CryptoPanel v-model="falconResult.data" label="签名 (HEX)" type="result"
                       :success="falconResult.success" copyable :group-hex="false" class="break-all text-[11px]" />
          <div v-if="falconResult.error || falconResult.success !== null" class="mt-2 text-xs"
               :class="falconResult.success ? 'text-emerald-400' : 'text-red-400'">
            {{ falconResult.error || (falconResult.op === 'verify'
                ? (falconResult.success ? '签名验证通过' : '签名验证失败')
                : (falconResult.success ? '签名成功' : '签名失败')) }}
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
              <tr v-for="r in falconParamInfo" :key="r.name" class="border-t"
                  :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <td class="py-1 font-mono">{{ r.name }}</td>
                <td class="text-right">{{ r.pk }}</td>
                <td class="text-right">{{ r.sig }}</td>
                <td class="text-right">{{ r.nist }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- HQC -->
    <div v-if="activeTab === 'hqc'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <div class="card">
          <div class="flex items-center gap-2 mb-3">
            <span class="badge">FIPS 207</span>
            <p class="text-sm font-medium">HQC — 准循环码密钥封装</p>
          </div>
          <label class="input-label">参数集</label>
          <Dropdown
            v-model="hqc.paramSet"
            :options="hqcParamInfo.map(p => ({ value: p.name, label: p.name + ' (' + p.nist + ')' }))"
            class="mb-3"
          />
          <button @click="genHQCKey" class="btn-secondary w-full justify-center mb-3">
            <KeyIcon class="w-3.5 h-3.5" /> 生成密钥对
          </button>
          <div v-if="hqcKeys.publicKey" class="space-y-2">
            <label class="input-label text-orange-300">私钥</label>
            <div class="relative">
              <textarea readonly class="result-area ck-key-hex !min-h-[72px] text-orange-300 text-[12px] font-mono w-full resize-none bg-transparent outline-none border-none overflow-y-auto pb-7" :value="hqcKeys.privateKey"></textarea>
              <span class="bytes-badge-inside">
                {{ base64ByteLen(hqcKeys.privateKey) + ' bytes' }}
              </span>
            </div>
            <label class="input-label text-cyan-400">公钥</label>
            <div class="relative">
              <textarea readonly class="result-area ck-key-hex !min-h-[72px] text-cyan-300 text-[12px] font-mono w-full resize-none bg-transparent outline-none border-none overflow-y-auto pb-7" :value="hqcKeys.publicKey"></textarea>
              <span class="bytes-badge-inside">
                {{ base64ByteLen(hqcKeys.publicKey) + ' bytes' }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div class="sym-main">
        <div class="card space-y-3">
          <button @click="hqcEncap" :disabled="!hqcKeys.publicKey" class="btn-success w-full justify-center">
            <LockIcon class="w-3.5 h-3.5" /> 封装 (Encapsulate)
          </button>
          <div v-if="hqcEncapResult.ciphertext" class="space-y-2">
            <label class="input-label text-emerald-400">密文</label>
            <div class="relative">
              <textarea readonly class="result-area ck-key-hex !min-h-[64px] pb-7 text-emerald-300 text-[12px] font-mono w-full resize-none bg-transparent outline-none border-none" :value="hqcEncapResult.ciphertext"></textarea>
              <ByteBadge :model-value="hqcEncapResult.ciphertext" />
            </div>
            <label class="input-label text-yellow-300">共享密钥</label>
            <div class="relative">
              <div class="result-area pb-7 text-yellow-300 font-mono break-all">{{ hqcEncapResult.sharedSecret }}</div>
              <ByteBadge :model-value="hqcEncapResult.sharedSecret" />
            </div>
            <button @click="hqcDecap" :disabled="!hqcKeys.privateKey" class="btn-warning w-full justify-center">
              <UnlockIcon class="w-3.5 h-3.5" /> 解封装 (Decapsulate)
            </button>
            <div v-if="hqcDecapResult.data || hqcDecapResult.error" class="text-xs"
                 :class="hqcDecapResult.error ? 'text-red-400' : 'text-emerald-400'">
              {{ hqcDecapResult.error || (hqcDecapResult.data === hqcEncapResult.sharedSecret ? '共享密钥一致，密钥交换成功' : '共享密钥不匹配') }}
            </div>
          </div>
        </div>
        <div class="card">
          <p class="card-title">参数对比</p>
          <table class="w-full text-xs">
            <thead><tr :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
              <th class="text-left pb-1">参数集</th>
              <th class="text-right pb-1">公钥</th>
              <th class="text-right pb-1">密文</th>
              <th class="text-right pb-1">安全</th>
            </tr></thead>
            <tbody :class="isDark ? 'text-dark-text' : 'text-light-text'">
              <tr v-for="r in hqcParamInfo" :key="r.name" class="border-t"
                  :class="isDark ? 'border-dark-border' : 'border-light-border'">
                <td class="py-1 font-mono">{{ r.name }}</td>
                <td class="text-right">{{ r.pk }}</td>
                <td class="text-right">{{ r.ct }}</td>
                <td class="text-right">{{ r.nist }}</td>
              </tr>
            </tbody>
          </table>
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
                <label class="input-label !mb-0 text-orange-300">私钥</label>
                <button @click="copy(xwingKeys.privateKey)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="relative">
                <textarea readonly class="result-area ck-key-hex !min-h-[64px] text-orange-300 text-[12px] font-mono w-full resize-none bg-transparent outline-none border-none overflow-y-auto pb-7" :value="xwingKeys.privateKey"></textarea>
                <span class="bytes-badge-inside">
                  {{ base64ByteLen(xwingKeys.privateKey) + ' bytes' }}
                </span>
              </div>
            </div>
            <div>
              <div class="flex justify-between mb-1">
                <label class="input-label !mb-0 text-cyan-400">公钥 (1216B = ML-KEM-768 + X25519)</label>
                <button @click="copy(xwingKeys.publicKey)" class="ck-copy-btn"><CopyIcon class="w-3 h-3" /></button>
              </div>
              <div class="relative">
                <textarea readonly class="result-area ck-key-hex !min-h-[64px] text-cyan-300 text-[12px] font-mono w-full resize-none bg-transparent outline-none border-none overflow-y-auto pb-7" :value="xwingKeys.publicKey"></textarea>
                <span class="bytes-badge-inside">
                  {{ base64ByteLen(xwingKeys.publicKey) + ' bytes' }}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div class="card space-y-2">
          <button @click="xwingEncap" class="btn-success w-full justify-center"><LockIcon class="w-3.5 h-3.5" /> 封装 (Encapsulate)</button>
          <div v-if="xwingEncapResult.ciphertext" class="space-y-2 animate-in fade-in">
            <div>
              <label class="input-label text-emerald-400">密文</label>
              <div class="relative">
                <textarea readonly class="result-area ck-key-hex !min-h-[48px] pb-7 text-emerald-300 text-[12px] font-mono w-full resize-none bg-transparent outline-none border-none" :value="xwingEncapResult.ciphertext"></textarea>
                <ByteBadge :model-value="xwingEncapResult.ciphertext" />
              </div>
            </div>
            <div>
              <label class="input-label text-violet-400">共享密钥</label>
              <div class="relative">
                <div class="result-area ck-key-hex !min-h-0 pb-7 text-violet-300 text-[12px] font-mono break-all">{{ xwingEncapResult.sharedSecret }}</div>
                <ByteBadge :model-value="xwingEncapResult.sharedSecret" />
              </div>
            </div>
            <button @click="xwingDecap" class="btn-warning w-full justify-center"><UnlockIcon class="w-3.5 h-3.5" /> 解封装 (Decapsulate)</button>
            <div v-if="xwingDecapResult.data || xwingDecapResult.error" class="animate-in fade-in">
              <label class="input-label" :class="xwingDecapResult.error ? 'text-red-400' : 'text-emerald-400'">解封装结果</label>
              <div class="relative">
                <div class="result-area ck-key-hex !min-h-0 pb-7 text-[12px] font-mono break-all"
                     :class="xwingDecapResult.error ? 'text-red-400' : 'text-emerald-400'">
                  {{ xwingDecapResult.error || xwingDecapResult.data }}
                </div>
                <ByteBadge :model-value="xwingDecapResult.data" />
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

    <!-- TLS 1.3 Key Exchange -->
    <div v-if="activeTab === 'tls13'" class="grid grid-cols-2 gap-4 animate-fade-in">
      <div class="space-y-3">
        <Card>
          <div class="flex items-center gap-2 mb-3">
            <span class="badge bg-blue-500/20 text-blue-400">RFC 8446</span>
            <p class="text-sm font-medium">TLS 1.3 混合密钥交换</p>
          </div>
          <div>
            <label class="input-label">密钥交换组</label>
            <Dropdown
              v-model="tls13.group"
              :options="tls13Groups"
              class="mb-3"
            />
          </div>
          <Button variant="secondary" block @click="genTLS13Key" class="mb-3">
            <KeyIcon class="w-3.5 h-3.5" /> 生成密钥对
          </Button>
          <div v-if="tls13Keys.publicKey" class="space-y-2 flex-1 min-h-0 flex flex-col">
            <div class="flex-1 min-h-0 flex flex-col">
              <div class="flex justify-between mb-1 shrink-0">
                <label class="input-label !mb-0 text-orange-300">私钥</label>
                <Button variant="tool" size="sm" @click="copy(tls13Keys.privateKey)"><CopyIcon class="w-3 h-3" /></Button>
              </div>
              <div class="relative flex-1">
                <textarea readonly class="result-area ck-key-hex !min-h-[48px] text-orange-300 text-[12px] font-mono w-full h-full resize-none bg-transparent outline-none border-none overflow-y-auto pb-7" :value="tls13Keys.privateKey"></textarea>
                <span class="bytes-badge-inside">
                  {{ base64ByteLen(tls13Keys.privateKey) + ' bytes' }}
                </span>
              </div>
            </div>
            <div class="flex-1 min-h-0 flex flex-col mt-2">
              <div class="flex justify-between mb-1 shrink-0">
                <label class="input-label !mb-0 text-cyan-400">公钥</label>
                <Button variant="tool" size="sm" @click="copy(tls13Keys.publicKey)"><CopyIcon class="w-3 h-3" /></Button>
              </div>
              <div class="relative flex-1">
                <textarea readonly class="result-area ck-key-hex !min-h-[48px] text-cyan-300 text-[12px] font-mono w-full h-full resize-none bg-transparent outline-none border-none overflow-y-auto pb-7" :value="tls13Keys.publicKey"></textarea>
                <span class="bytes-badge-inside">
                  {{ base64ByteLen(tls13Keys.publicKey) + ' bytes' }}
                </span>
              </div>
            </div>
          </div>
        </Card>
      </div>

      <div class="space-y-3 sym-main">
        <Card title="密钥交换演示" class="space-y-3">
          <Button variant="success" block @click="doTLS13Exchange">
            <LockIcon class="w-3.5 h-3.5" /> 执行完整密钥交换
          </Button>
          <div v-if="tls13Result.success || tls13Result.error" class="space-y-2 animate-in fade-in">
            <div v-if="tls13Result.data">
              <div class="flex justify-between mb-1">
                <label class="input-label !mb-0 text-emerald-400">共享密钥 (Shared Secret)</label>
                <Button variant="tool" size="sm" @click="copy(tls13Result.data)"><CopyIcon class="w-3 h-3" /></Button>
              </div>
              <div class="relative">
                <div class="result-area pb-7 text-emerald-300 font-mono text-[12px]">{{ tls13Result.data }}</div>
                <ByteBadge :model-value="tls13Result.data" />
              </div>
            </div>
            <div v-if="tls13Result.extra">
              <label class="input-label text-violet-400">密钥交换详情</label>
              <div class="result-area text-violet-300 text-[11px] whitespace-pre-wrap">{{ tls13Result.extra }}</div>
            </div>
            <div v-if="tls13Result.error">
              <label class="input-label text-red-400">错误</label>
              <div class="result-area text-red-400 text-[12px]">{{ tls13Result.error }}</div>
            </div>
          </div>
        </Card>
        <Card title="TLS 1.3 密钥交换原理">
          <div class="text-xs space-y-3 leading-relaxed" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <!-- 什么是密钥交换 -->
            <div class="p-3 rounded-xl border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-2 text-blue-400">什么是密钥交换？</p>
              <p>通信双方通过密码学协议协商出一个<strong>共享密钥</strong>，用于后续通信的对称加密。TLS 1.3 使用 Diffie-Hellman 类协议实现密钥交换，保证即使通信被窃听，攻击者也无法计算出共享密钥。</p>
            </div>

            <!-- 为什么需要混合 -->
            <div class="p-3 rounded-xl border border-amber-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-2 text-amber-400">为什么需要"混合"密钥交换？</p>
              <p class="mb-2">量子计算机威胁：Shor 算法可在多项式时间内破解传统 ECDH/RSA。</p>
              <p class="mb-2">混合模式的<strong>双重保险</strong>策略：</p>
              <p>• 经典算法 (X25519) 被破解 → 后量子算法 (ML-KEM) 仍安全</p>
              <p>• 后量子算法被破解 → 经典算法仍安全</p>
              <p>• 只有两种算法<strong>同时</strong>被攻破，通信才会被破解</p>
            </div>

            <!-- 经典 vs 后量子 -->
            <div class="p-3 rounded-xl border border-violet-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-2 text-violet-400">经典 vs 后量子算法对比</p>
              <div class="grid grid-cols-2 gap-2 mt-2">
                <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                  <p class="font-semibold text-cyan-400 mb-1">经典：X25519 (ECDH)</p>
                  <p>• 基于椭圆曲线离散对数问题</p>
                  <p>• 公钥 32 字节，计算快</p>
                  <p>• 量子计算机可破解</p>
                </div>
                <div class="p-2 rounded-lg border" :class="isDark ? 'border-dark-border' : 'border-light-border'">
                  <p class="font-semibold text-emerald-400 mb-1">后量子：ML-KEM-768</p>
                  <p>• 基于模学习误差问题 (Module-LWE)</p>
                  <p>• 公钥 1184 字节，密文 1088 字节</p>
                  <p>• 能抵抗量子攻击</p>
                </div>
              </div>
            </div>

            <!-- 工作流程 -->
            <div class="p-3 rounded-xl border border-emerald-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-2 text-emerald-400">混合密钥交换工作流程</p>
              <div class="space-y-2">
                <div class="flex items-start gap-2">
                  <span class="shrink-0 w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-[10px] font-bold">1</span>
                  <p><strong>Client</strong> 生成两对密钥：X25519 密钥对 + ML-KEM-768 密钥对</p>
                </div>
                <div class="flex items-start gap-2">
                  <span class="shrink-0 w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-[10px] font-bold">2</span>
                  <p><strong>Client</strong> 将两个公钥打包成 KeyShare，通过 ClientHello 发送给 Server</p>
                </div>
                <div class="flex items-start gap-2">
                  <span class="shrink-0 w-5 h-5 rounded-full bg-violet-500/20 text-violet-400 flex items-center justify-center text-[10px] font-bold">3</span>
                  <p><strong>Server</strong> 分别处理两个密钥交换，计算出两个共享密钥</p>
                </div>
                <div class="flex items-start gap-2">
                  <span class="shrink-0 w-5 h-5 rounded-full bg-violet-500/20 text-violet-400 flex items-center justify-center text-[10px] font-bold">4</span>
                  <p><strong>Server</strong> 将两个公钥打包成 KeyShare，通过 ServerHello 发送给 Client</p>
                </div>
                <div class="flex items-start gap-2">
                  <span class="shrink-0 w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-[10px] font-bold">5</span>
                  <p><strong>Client</strong> 分别计算两个共享密钥</p>
                </div>
                <div class="flex items-start gap-2">
                  <span class="shrink-0 w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-[10px] font-bold">6</span>
                  <p>双方将两个共享密钥通过 <strong>KDF</strong> 派生出最终的会话密钥</p>
                </div>
              </div>
              <div class="mt-3 p-2 rounded-lg border border-amber-400/20" :class="isDark ? 'bg-amber-500/5' : 'bg-amber-50'">
                <p class="text-[11px]"><strong>共享密钥计算公式：</strong>Session_Key = KDF(X25519_shared_secret || ML-KEM_shared_secret)</p>
              </div>
            </div>

            <!-- 支持的组 -->
            <div class="p-3 rounded-xl border border-cyan-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-2 text-cyan-400">支持的密钥交换组</p>
              <div class="grid grid-cols-2 gap-2">
                <div>
                  <p class="font-semibold text-[11px] mb-1">经典组：</p>
                  <p>• X25519 (0x001D)</p>
                  <p>• P-256 (0x0017)</p>
                  <p>• P-384 (0x0018)</p>
                  <p>• P-521 (0x0019)</p>
                  <p>• SM2 (0x0029)</p>
                </div>
                <div>
                  <p class="font-semibold text-[11px] mb-1">混合组：</p>
                  <p>• X25519+ML-KEM-768 (0x11EC)</p>
                  <p>• P-256+ML-KEM-768 (0x11EB)</p>
                  <p>• P-384+ML-KEM-1024 (0x11ED)</p>
                  <p>• SM2+ML-KEM-768 (0x11EE)</p>
                </div>
              </div>
            </div>

            <!-- 标准化 -->
            <div class="p-3 rounded-xl border border-rose-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-bold mb-2 text-rose-400">标准化状态</p>
              <p>• 经典密钥交换：RFC 8446 (TLS 1.3 标准)</p>
              <p>• 混合密钥交换：draft-ietf-tls-hybrid-design (IETF 草案)</p>
              <p>• ML-KEM 算法：FIPS 203 (NIST 标准)</p>
              <p>• 混合组 ID：IANA 已分配临时代码点</p>
            </div>
          </div>
        </Card>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { storeToRefs } from 'pinia'
import { AtomIcon, KeyIcon, LockIcon, UnlockIcon, PenIcon, CheckCircleIcon, XCircleIcon, CopyIcon, InfoIcon, XIcon } from '@lucide/vue'
import Card from '../components/Card.vue'
import Input from '../components/Input.vue'
import Button from '../components/Button.vue'
import ResultArea from '../components/ResultArea.vue'
import AlgorithmDrawer from '../components/AlgorithmDrawer.vue'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import Dropdown from '../components/Dropdown.vue'
import ByteBadge from '../components/ByteBadge.vue'
import {
  MLKEMKeyGen, MLKEMEncapsulate, MLKEMDecapsulate,
  MLDSAKeyGen, MLDSASign, MLDSAVerify,
  SLHDSAKeyGen, SLHDSASign, SLHDSAVerify,
  XWingKeyGen, XWingEncapsulate, XWingDecapsulate,
  TLS13KeyGen, TLS13FullExchange,
  AigisKeyGen, AigisSign, AigisVerify,
  FalconKeyGen, FalconSign, FalconVerify,
  HQCKeyGen, HQCEncapsulate, HQCDecapsulate,
} from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'mlkem', label: 'ML-KEM (Kyber)' },
  { id: 'mldsa', label: 'ML-DSA (Dilithium)' },
  { id: 'slhdsa', label: 'SLH-DSA (SPHINCS+)' },
  { id: 'aigis', label: 'AIGIS-sig (国密)' },
  { id: 'xwing', label: 'X-Wing' },
  { id: 'falcon', label: 'FALCON' },
  { id: 'hqc', label: 'HQC' },
  { id: 'tls13', label: 'TLS 1.3 混合交换' },
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
  aigis: {
    title: 'AIGIS-sig 算法原理',
    content: `AIGIS-sig 是中国科学院信息工程研究所设计的基于格的数字签名算法，参加中国国密 PQC 算法征集。
- 安全性：基于模块学习误差 (MLWE) 和模块短整数解 (MSIS) 难题。
- 特点：支持 SM3 / SHAKE 双哈希模式，提供 AIGIS-sig-1/2/3 三组参数。
- 参数集：AIGIS-sig-1 (pk 1056B / sk 2448B / sig 1852B)、AIGIS-sig-2 (pk 1312B / sk 3376B / sig 2445B)、AIGIS-sig-3 (pk 1568B / sk 3888B / sig 3046B)。
- 说明：已按官方 PQMagic 参考实现完整移植，并通过官方测试向量验证。`
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
  },
  tls13: {
    title: 'TLS 1.3 混合密钥交换原理',
    content: `什么是 TLS 1.3 密钥交换？
TLS 1.3 是最新的安全传输层协议标准 (RFC 8446)，密钥交换是其核心环节。通信双方通过密钥交换协商出一个共享密钥，用于后续通信的对称加密。

为什么需要混合密钥交换？
量子计算机的出现威胁到传统密码算法的安全。混合密钥交换将经典算法 (如 X25519) 与后量子算法 (如 ML-KEM) 结合，实现"双重保险"：
- 即使后量子算法被破解，经典算法仍提供安全保障
- 即使经典算法被量子计算机破解，后量子算法仍提供安全保障
- 只有两种算法同时被攻破，通信才会被破解

经典密钥交换 (以 X25519 为例)：
• 基于椭圆曲线 Diffie-Hellman (ECDH) 协议
• 安全性基于椭圆曲线离散对数问题 (ECDLP)
• 密钥尺寸小 (32 字节)，计算速度快
• 量子计算机可用 Shor 算法在多项式时间内破解

后量子密钥交换 (以 ML-KEM-768 为例)：
• 基于模块格的密钥封装机制 (Module-Lattice KEM)
• 安全性基于模学习误差问题 (Module-LWE)，被认为能抵抗量子攻击
• 密钥尺寸较大 (公钥 1184 字节，密文 1088 字节)
• 已被 NIST 标准化为 FIPS 203

混合模式工作原理 (以 X25519+ML-KEM-768 为例)：
1. Client 生成两对密钥：X25519 密钥对 + ML-KEM-768 密钥对
2. Client 将两个公钥打包成 KeyShare 发送给 Server
3. Server 分别处理两个密钥交换，得到两个共享密钥
4. Server 将两个公钥打包成 KeyShare 发送给 Client
5. Client 分别计算两个共享密钥
6. 双方将两个共享密钥通过 KDF 派生出最终的会话密钥

安全性分析：
• 组合安全性：共享密钥 = KDF(X25519_shared || ML-KEM_shared)
• 攻击者必须同时破解两种算法才能获取会话密钥
• 满足"组合不低于最强"的安全保证

支持的密钥交换组：
• 经典组：X25519 (0x001D)、P-256 (0x0017)、P-384 (0x0018)、P-521 (0x0019)、SM2 (0x0029)
• 混合组：X25519+ML-KEM-768 (0x11EC)、P-256+ML-KEM-768 (0x11EB)、P-384+ML-KEM-1024 (0x11ED)、SM2+ML-KEM-768 (0x11EE)

标准化状态：
• 经典密钥交换：RFC 8446 (TLS 1.3)
• 混合密钥交换：draft-ietf-tls-hybrid-design (IETF 草案)
• ML-KEM：FIPS 203 (NIST 标准)
• 混合组 ID：IANA 已分配临时代码点`
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

// FALCON
const falcon = reactive({ paramSet: 'Falcon-512', data: '' })
const falconKeys = reactive({ privateKey: '', publicKey: '' })
const falconResult = reactive({ data: '', error: '', success: null, op: '' })
const falconParamInfo = [
  { name: 'Falcon-512',  pk: '897B',  sig: '809B',  nist: 'NIST-1' },
  { name: 'Falcon-1024', pk: '1793B', sig: '1577B', nist: 'NIST-5' },
]

async function genFalconKey() {
  falconKeys.privateKey = ''; falconKeys.publicKey = ''
  falconResult.data = ''; falconResult.error = ''; falconResult.success = null; falconResult.op = ''
  const r = await FalconKeyGen(falcon.paramSet)
  if (r.success) { falconKeys.privateKey = r.privateKey; falconKeys.publicKey = r.publicKey }
  else { falconResult.error = r.error || '密钥生成失败'; falconResult.success = false }
}
async function falconSign() {
  const r = await FalconSign({ privateKey: falconKeys.privateKey, data: falcon.data, paramSet: falcon.paramSet })
  falconResult.data = r.data; falconResult.error = r.error; falconResult.success = r.success; falconResult.op = 'sign'
}
async function falconVerify() {
  const r = await FalconVerify({ publicKey: falconKeys.publicKey, data: falcon.data, signature: falconResult.data, paramSet: falcon.paramSet })
  falconResult.data = r.data; falconResult.error = r.error; falconResult.success = r.success; falconResult.op = 'verify'
}

// HQC
const hqc = reactive({ paramSet: 'HQC-128' })
const hqcKeys = reactive({ privateKey: '', publicKey: '' })
const hqcEncapResult = reactive({ ciphertext: '', sharedSecret: '', error: '' })
const hqcDecapResult = reactive({ data: '', error: '' })
const hqcParamInfo = [
  { name: 'HQC-128', pk: '2241B', ct: '4433B',  nist: 'NIST-1' },
  { name: 'HQC-192', pk: '4514B', ct: '8978B',  nist: 'NIST-3' },
  { name: 'HQC-256', pk: '7237B', ct: '14421B', nist: 'NIST-5' },
]

async function genHQCKey() {
  hqcKeys.privateKey = ''; hqcKeys.publicKey = ''
  hqcEncapResult.ciphertext = ''; hqcEncapResult.sharedSecret = ''; hqcEncapResult.error = ''
  hqcDecapResult.data = ''; hqcDecapResult.error = ''
  const r = await HQCKeyGen(hqc.paramSet)
  if (r.success) { hqcKeys.privateKey = r.privateKey; hqcKeys.publicKey = r.publicKey }
  else { hqcDecapResult.error = r.error || '密钥生成失败' }
}
async function hqcEncap() {
  const r = await HQCEncapsulate({ publicKey: hqcKeys.publicKey, paramSet: hqc.paramSet })
  if (r.success) {
    hqcEncapResult.ciphertext = r.ciphertext
    hqcEncapResult.sharedSecret = r.sharedSecret
    hqcEncapResult.error = ''
  } else {
    hqcEncapResult.error = r.error || '封装失败'
  }
}
async function hqcDecap() {
  const r = await HQCDecapsulate({ privateKey: hqcKeys.privateKey, ciphertext: hqcEncapResult.ciphertext, paramSet: hqc.paramSet })
  hqcDecapResult.data = r.data; hqcDecapResult.error = r.error
}

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

// AIGIS-sig
const aigis = reactive({ paramSet: 'AIGIS-sig-1', data: '' })
const aigisKeys = reactive({ privateKey: '', publicKey: '' })
const aigisKeyError = reactive({ error: '' })
const aigisResult = reactive({ data: '', error: '', success: null })

async function genAigisKey() {
  try {
    aigisKeys.privateKey = ''; aigisKeys.publicKey = ''
    aigisResult.data = ''; aigisResult.error = ''; aigisResult.success = null
    const r = await AigisKeyGen(aigis.paramSet)
    if (r.success) {
      aigisKeys.privateKey = r.privateKey
      aigisKeys.publicKey = r.publicKey
      aigisKeyError.error = ''
    } else {
      aigisKeyError.error = r.error || '密钥生成失败'
    }
  } catch (e) {
    aigisKeyError.error = String(e)
  }
}
async function aigisSign() {
  aigisResult.data = ''; aigisResult.error = ''; aigisResult.success = null
  const r = await AigisSign({ privateKey: aigisKeys.privateKey, data: aigis.data, paramSet: aigis.paramSet })
  aigisResult.data = r.data; aigisResult.error = r.error; aigisResult.success = r.success
}
async function aigisVerify() {
  const r = await AigisVerify({ publicKey: aigisKeys.publicKey, data: aigis.data, signature: aigisResult.data, paramSet: aigis.paramSet })
  aigisResult.data = r.data; aigisResult.error = r.error; aigisResult.success = r.success
}

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

// TLS 1.3 Key Exchange
const tls13 = reactive({ group: 'X25519MLKEM768' })
const tls13Keys = reactive({ publicKey: '', privateKey: '' })
const tls13Result = reactive({ success: false, data: '', extra: '', error: '' })

const tls13Groups = [
  { value: 'X25519', label: 'X25519 (经典)' },
  { value: 'P256', label: 'P-256 (经典)' },
  { value: 'P384', label: 'P-384 (经典)' },
  { value: 'P521', label: 'P-521 (经典)' },
  { value: 'SM2', label: 'SM2 (国密)' },
  { value: 'X25519MLKEM768', label: 'X25519+ML-KEM-768 (混合)' },
  { value: 'P256MLKEM768', label: 'P-256+ML-KEM-768 (混合)' },
  { value: 'P384MLKEM1024', label: 'P-384+ML-KEM-1024 (混合)' },
  { value: 'SM2MLKEM768', label: 'SM2+ML-KEM-768 (混合)' },
]

async function genTLS13Key() {
  const r = await TLS13KeyGen(tls13.group)
  if (r.success) {
    tls13Keys.publicKey = r.publicKey
    tls13Keys.privateKey = r.privateKey
    tls13Result.success = false
    tls13Result.data = ''
    tls13Result.error = ''
  }
}

async function doTLS13Exchange() {
  const r = await TLS13FullExchange(tls13.group)
  tls13Result.success = r.success
  tls13Result.data = r.data
  tls13Result.extra = r.extra
  tls13Result.error = r.error
}

async function copy(text) {
  if (!text) return
  await navigator.clipboard.writeText(text)
  store.showToast('已复制')
}

function base64ByteLen(b64) {
  if (!b64) return 0
  const s = String(b64).trim()
  // 十六进制字符串: 每 2 个字符 = 1 字节
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return s.length / 2
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

/* 字节角标样式统一使用全局 .bytes-badge-inside (见 styles/components.css) */
</style>
