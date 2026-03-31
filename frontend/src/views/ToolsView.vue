<template>
  <PageLayout :title="pageTitle" :subtitle="pageSubtitle"
              icon-bg="bg-amber-500/20"
              :tabs="visibleTabs" :active-tab="activeTab" @tab-change="handleTabChange">
    <template #icon>
      <WrenchIcon class="w-4 h-4 text-amber-400" />
    </template>

    <!-- Encoding -->
    <div v-if="activeTab === 'encode'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <!-- Str <-> Hex -->
        <div class="ck-card">
          <p class="ck-section-title">字符串 ↔ Hex</p>
          <CryptoPanel v-model="enc.input" label="输入" type="textarea" :rows="3" clearable placeholder="输入文本或hex..." />
          <div class="flex gap-2 mt-2">
            <button @click="strToHex" class="ck-btn-primary flex-1 justify-center text-xs">文本 → Hex</button>
            <button @click="hexToStr" class="ck-btn-secondary flex-1 justify-center text-xs">Hex → 文本</button>
          </div>
        </div>

        <!-- Base64 -->
        <div class="ck-card">
          <p class="ck-section-title">Base64</p>
          <div class="grid grid-cols-2 gap-2 mb-2">
            <div>
              <label class="ck-label">编码标准</label>
              <select v-model="b64.format" class="ck-select">
                <option value="Standard">Standard</option>
                <option value="URL">URL安全</option>
                <option value="NoPadding">无填充</option>
              </select>
            </div>
            <div>
              <label class="ck-label">输入格式</label>
              <select v-model="b64.isHex" class="ck-select">
                <option :value="false">文本</option>
                <option :value="true">Hex</option>
              </select>
            </div>
          </div>
          <CryptoPanel v-model="b64.input" label="输入" type="textarea" :rows="3" clearable />
          <div class="flex gap-2 mt-2">
            <button @click="b64Encode" class="ck-btn-primary flex-1 justify-center text-xs">编码</button>
            <button @click="b64Decode" class="ck-btn-secondary flex-1 justify-center text-xs">解码</button>
          </div>
        </div>
      </div>

      <div class="ck-stack">
        <!-- URL Encode -->
        <div class="ck-card">
          <p class="ck-section-title">URL 编解码</p>
          <CryptoPanel v-model="urlEnc.input" label="输入" type="textarea" :rows="3" clearable />
          <div class="flex gap-2 mt-2">
            <button @click="doUrlEncode" class="ck-btn-primary flex-1 justify-center text-xs">URL编码</button>
            <button @click="doUrlDecode" class="ck-btn-secondary flex-1 justify-center text-xs">URL解码</button>
          </div>
        </div>

        <!-- Unicode -->
        <div class="ck-card">
          <p class="ck-section-title">Unicode 转义</p>
          <CryptoPanel v-model="unicode.input" label="输入" type="textarea" :rows="3" clearable />
          <div class="flex gap-2 mt-2">
            <button @click="unicodeEnc" class="ck-btn-primary flex-1 justify-center text-xs">编码 (\u转义)</button>
            <button @click="unicodeDec" class="ck-btn-secondary flex-1 justify-center text-xs">解码</button>
          </div>
        </div>

        <!-- Result -->
        <div class="ck-card">
          <CryptoPanel v-model="encResult.data" label="结果" type="result" :success="encResult.success" copyable compact />
          <div v-if="encResult.error" class="mt-2 text-xs text-red-400">{{ encResult.error }}</div>
        </div>
      </div>
    </div>

    <!-- XOR / Bitwise -->
    <div v-if="activeTab === 'xor'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">XOR 异或运算</p>
          <div>
            <label class="ck-label">操作数 A (hex)</label>
            <input v-model="xor.a" class="ck-input font-mono ck-trim-space" placeholder="hex格式..." />
          </div>
          <div>
            <label class="ck-label">操作数 B (hex)</label>
            <input v-model="xor.b" class="ck-input font-mono ck-trim-space" placeholder="hex格式..." />
          </div>
          <button @click="doXOR" class="ck-btn-primary w-full justify-center">
            <ZapIcon class="w-3.5 h-3.5" /> A ⊕ B
          </button>
        </div>

        <!-- Base convert -->
        <div class="ck-card space-y-3">
          <p class="ck-section-title">进制转换</p>
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="ck-label">源进制</label>
              <select v-model="baseConv.from" class="ck-select">
                <option :value="2">二进制</option>
                <option :value="8">八进制</option>
                <option :value="10">十进制</option>
                <option :value="16">十六进制</option>
              </select>
            </div>
            <div>
              <label class="ck-label">目标进制</label>
              <select v-model="baseConv.to" class="ck-select">
                <option :value="2">二进制</option>
                <option :value="8">八进制</option>
                <option :value="10">十进制</option>
                <option :value="16">十六进制</option>
              </select>
            </div>
          </div>
          <input v-model="baseConv.value" class="ck-input font-mono ck-trim-space" placeholder="输入数值..." />
          <button @click="doBaseConvert" class="ck-btn-primary w-full justify-center text-sm">转换</button>
        </div>
      </div>

      <div class="ck-stack">
        <div class="ck-card">
          <CryptoPanel v-model="xorResult.data" label="运算结果" type="result" :success="xorResult.success" copyable compact />
          <div v-if="xorResult.error" class="mt-2 text-xs text-red-400">{{ xorResult.error }}</div>
        </div>
      </div>
    </div>

    <!-- Random -->
    <div v-if="activeTab === 'random'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">随机数生成</p>
          <div>
              <label class="ck-label">字节长度</label>
              <div class="flex gap-2 flex-wrap mb-2">
              <button v-for="n in [8, 16, 24, 32, 48, 64]" :key="n"
                      class="ck-chip-btn"
                      :class="{ active: rng.length === n }"
                      @click="rng.length = n">{{ n }}B</button>
            </div>
            <input v-model.number="rng.length" type="number" min="1" max="4096" class="ck-input" />
          </div>
          <div>
            <label class="ck-label">输出格式</label>
            <select v-model="rng.format" class="ck-select">
              <option value="hex">Hex</option>
              <option value="base64">Base64</option>
            </select>
          </div>
          <button @click="doGenRandom" class="ck-btn-primary w-full justify-center">
            <RefreshCwIcon class="w-3.5 h-3.5" /> 生成随机数
          </button>
        </div>

        <div class="ck-card">
          <CryptoPanel v-model="rngResult.data" label="随机数结果" type="result" :success="rngResult.success" copyable compact />
        </div>

        <div class="ck-card space-y-3">
          <p class="ck-section-title">XChaCha20-Poly1305 Key/Nonce</p>
          <div>
            <label class="ck-label">Key (32字节)</label>
            <div class="ck-result ck-result-sm !min-h-0 text-xs font-mono break-all">{{ xchacha.key }}</div>
            <div v-if="xchacha.key" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-amber-400 border-amber-500/20 bg-amber-500/5">
                {{ (xchacha.key.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <div>
            <label class="ck-label">Nonce (24字节)</label>
            <div class="ck-result ck-result-sm !min-h-0 text-xs font-mono break-all">{{ xchacha.nonce }}</div>
            <div v-if="xchacha.nonce" class="flex gap-3 mt-1">
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md border text-cyan-400 border-cyan-500/20 bg-cyan-500/5">
                {{ (xchacha.nonce.replace(/\s+/g, '').length / 2) + ' bytes' }}
              </span>
            </div>
          </div>
          <button @click="genXChaCha" class="ck-btn-muted w-full justify-center text-sm">生成 Key / Nonce</button>
        </div>
      </div>

      <div class="ck-stack">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">数据填充工具</p>
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="ck-label">填充模式</label>
              <select v-model="pad.mode" class="ck-select">
                <option>PKCS7</option><option>PKCS5</option>
                <option>Zero</option><option>ISO10126</option><option>ANSIX923</option>
              </select>
            </div>
            <div>
              <label class="ck-label">块大小</label>
              <select v-model="pad.blockSize" class="ck-select">
                <option :value="8">8字节(DES)</option>
                <option :value="16">16字节(AES)</option>
              </select>
            </div>
          </div>
          <CryptoPanel v-model="pad.data" label="数据 (hex)" type="input" clearable />
          <div class="flex gap-2">
            <button @click="doPadApply" class="ck-btn-primary flex-1 text-xs justify-center">添加填充</button>
            <button @click="doPadRemove" class="ck-btn-secondary flex-1 text-xs justify-center">移除填充</button>
          </div>
        </div>
        <div class="ck-card">
          <CryptoPanel v-model="padResult.data" label="填充结果 (hex)" type="result" :success="padResult.success" copyable compact />
          <div v-if="padResult.error" class="mt-2 text-xs text-red-400">{{ padResult.error }}</div>
        </div>
        <div class="ck-card">
          <p class="ck-section-title">填充说明</p>
          <div class="space-y-2 text-[12px] leading-5" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="ck-note-card">
              <p class="ck-note-title text-violet-400">常见块长</p>
              <p>DES / 3DES 通常用 8 字节块长，AES / SM4 通常用 16 字节块长。</p>
            </div>
            <div class="ck-note-card">
              <p class="ck-note-title text-amber-400">联调提醒</p>
              <p>移除填充失败时，通常是块长、模式或输入编码和对端不一致。</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Timestamp -->
    <div v-if="activeTab === 'timestamp'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">时间戳转换</p>
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="ck-label">输入格式</label>
              <select v-model="ts.from" class="ck-select">
                <option value="unix10">Unix (秒)</option>
                <option value="unix13">Unix (毫秒)</option>
                <option value="rfc3339">RFC3339</option>
                <option value="datetime">日期时间</option>
              </select>
            </div>
            <div>
              <label class="ck-label">输出格式</label>
              <select v-model="ts.to" class="ck-select">
                <option value="unix10">Unix (秒)</option>
                <option value="unix13">Unix (毫秒)</option>
                <option value="rfc3339">RFC3339</option>
                <option value="datetime">日期时间</option>
              </select>
            </div>
          </div>
          <div>
            <label class="ck-label">时区</label>
            <select v-model="ts.timezone" class="ck-select">
              <option value="Asia/Shanghai">Asia/Shanghai (UTC+8)</option>
              <option value="UTC">UTC</option>
              <option value="America/New_York">America/New_York</option>
              <option value="Europe/London">Europe/London</option>
              <option value="Asia/Tokyo">Asia/Tokyo</option>
            </select>
          </div>
          <input v-model="ts.value" class="ck-input font-mono ck-trim-space" :placeholder="tsPlaceholder" />
          <div class="flex gap-2">
            <button @click="doTsConvert" class="ck-btn-primary flex-1 justify-center text-sm">转换</button>
            <button @click="nowTs" class="ck-btn-muted text-xs">当前时间</button>
          </div>
        </div>
      </div>
      <div class="ck-stack">
        <div class="ck-card">
          <CryptoPanel v-model="tsResult.data" label="转换结果" type="result" :success="tsResult.success" copyable compact />
          <div v-if="tsResult.error" class="mt-2 text-xs text-red-400">{{ tsResult.error }}</div>
        </div>
        <!-- Quick ref -->
        <div class="ck-card">
          <p class="ck-section-title">快速参考</p>
          <div class="space-y-1.5 text-xs" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="flex justify-between">
              <span>当前Unix(秒):</span>
              <span class="font-mono" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ nowUnix }}</span>
            </div>
            <div class="flex justify-between">
              <span>当前Unix(毫秒):</span>
              <span class="font-mono" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ nowUnixMs }}</span>
            </div>
            <div class="flex justify-between">
              <span>UTC时间:</span>
              <span class="font-mono" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ nowUTC }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ASN.1 -->
    <div v-if="activeTab === 'asn1'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">ASN.1 解析</p>
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="ck-label">输入格式</label>
              <select v-model="asn1.format" class="ck-select">
                <option value="auto">自动识别</option>
                <option value="pem">PEM</option>
                <option value="hex">Hex</option>
                <option value="base64">Base64</option>
                <option value="text">文本</option>
              </select>
            </div>
            <div class="flex items-end">
              <button @click="uploadAsn1File" class="ck-btn-muted w-full justify-center text-xs">
                <FolderOpenIcon class="w-3.5 h-3.5" /> 选择文件解析
              </button>
            </div>
          </div>
          <CryptoPanel v-model="asn1.input" label="输入 (可粘贴 PEM/DER/Hex/Base64)" type="textarea" :rows="3" clearable />
          <button @click="parseAsn1" class="ck-btn-primary w-full justify-center text-sm">解析</button>
        </div>
      </div>

      <div class="ck-stack">
        <div class="ck-card">
          <label class="ck-label">解析结果</label>
          <textarea readonly class="ck-result text-xs font-mono w-full min-h-[108px] resize-none bg-transparent outline-none border-none overflow-y-auto"
                    :value="asn1Result.data || (asn1Result.error ? '' : '结果将显示在这里...')"></textarea>
          <div v-if="asn1Result.error" class="mt-2 text-xs text-red-400">{{ asn1Result.error }}</div>
        </div>
      </div>
    </div>

    <!-- BaseX -->
    <div v-if="activeTab === 'base'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">Base32</p>
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="ck-label">字母表</label>
              <select v-model="b32.format" class="ck-select">
                <option value="Standard">Standard</option>
                <option value="Hex">Hex</option>
              </select>
            </div>
            <div>
              <label class="ck-label">输入格式</label>
              <select v-model="b32.isHex" class="ck-select">
                <option :value="false">文本</option>
                <option :value="true">Hex</option>
              </select>
            </div>
          </div>
          <label class="ck-label">
            <input v-model="b32.noPadding" type="checkbox" class="mr-2">不使用填充
          </label>
          <CryptoPanel v-model="b32.input" label="输入" type="textarea" :rows="3" clearable />
          <div class="flex gap-2">
            <button @click="doBase32Encode" class="ck-btn-primary flex-1 text-xs justify-center">编码</button>
            <button @click="doBase32Decode" class="ck-btn-secondary flex-1 text-xs justify-center">解码</button>
          </div>
        </div>

        <div class="ck-card space-y-3">
          <p class="ck-section-title">Base58</p>
          <div>
            <label class="ck-label">输入格式</label>
            <select v-model="b58.isHex" class="ck-select">
              <option :value="false">文本</option>
              <option :value="true">Hex</option>
            </select>
          </div>
          <CryptoPanel v-model="b58.input" label="输入" type="textarea" :rows="3" clearable />
          <div class="flex gap-2">
            <button @click="doBase58Encode" class="ck-btn-primary flex-1 text-xs justify-center">编码</button>
            <button @click="doBase58Decode" class="ck-btn-secondary flex-1 text-xs justify-center">解码</button>
          </div>
        </div>

        <div class="ck-card space-y-3">
          <p class="ck-section-title">Bech32</p>
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="ck-label">HRP</label>
              <input v-model="bech.hrp" class="ck-input font-mono ck-trim-space" />
            </div>
            <div>
              <label class="ck-label">输入格式</label>
              <select v-model="bech.isHex" class="ck-select">
                <option :value="true">Hex</option>
                <option :value="false">文本</option>
              </select>
            </div>
          </div>
          <CryptoPanel v-model="bech.input" label="编码输入" type="textarea" :rows="2" clearable />
          <button @click="doBech32Encode" class="ck-btn-primary w-full text-xs justify-center">编码</button>
          <CryptoPanel v-model="bech.decoded" label="待解码 Bech32" type="textarea" :rows="2" clearable />
          <button @click="doBech32Decode" class="ck-btn-secondary w-full text-xs justify-center">解码</button>
        </div>
      </div>

      <div class="ck-stack">
        <div class="ck-card">
          <CryptoPanel v-model="baseResult.data" label="结果" type="result" :success="baseResult.success" copyable compact />
          <div v-if="baseResult.error" class="mt-2 text-xs text-red-400">{{ baseResult.error }}</div>
        </div>
        <div class="ck-card">
          <p class="ck-section-title">说明</p>
          <div class="text-xs space-y-2" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-2.5 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-blue-400 mb-1">常见用途</p>
              <p>• Base32/58: 地址、序列号、短码。</p>
              <p>• Bech32: 地址编码 (如 BTC SegWit)。</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- JWT/JWK -->
    <div v-if="activeTab === 'jwt'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">JWT 解析/验证</p>
          <CryptoPanel v-model="jwt.token" label="JWT Token" type="textarea" :rows="3" clearable />
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="ck-label">密钥格式</label>
              <select v-model="jwt.keyFormat" class="ck-select">
                <option value="auto">自动识别</option>
                <option value="pem">PEM</option>
                <option value="jwk">JWK/JWKS</option>
                <option value="raw">原始文本</option>
              </select>
            </div>
            <label class="ck-label flex items-center gap-2 mt-5">
              <input v-model="jwt.verify" type="checkbox">验证签名
            </label>
          </div>
          <CryptoPanel v-model="jwt.key" label="密钥 (PEM/JWK/RAW)" type="textarea" :rows="3" clearable />
          <button @click="parseJwt" class="ck-btn-primary w-full justify-center text-sm">解析 / 验证</button>
        </div>
      </div>
      <div class="ck-stack">
        <div class="ck-card">
          <p class="ck-section-title">Header</p>
          <textarea readonly class="ck-result ck-result-sm text-xs font-mono w-full min-h-[72px] resize-none bg-transparent outline-none border-none"
                    :value="jwtResult.header"></textarea>
        </div>
        <div class="ck-card">
          <p class="ck-section-title">Payload</p>
          <textarea readonly class="ck-result ck-result-sm text-xs font-mono w-full min-h-[72px] resize-none bg-transparent outline-none border-none"
                    :value="jwtResult.payload"></textarea>
          <div v-if="jwt.verify" class="mt-2 text-xs" :class="jwtResult.valid ? 'text-emerald-400' : 'text-red-400'">
            {{ jwtResult.valid ? '签名验证通过' : '签名验证失败' }}
          </div>
          <div v-if="jwtResult.error" class="mt-1 text-xs text-red-400">{{ jwtResult.error }}</div>
        </div>
      </div>
    </div>

    <!-- Key/Cert -->
    <div v-if="activeTab === 'keycert'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">密钥格式转换</p>
          <div>
            <label class="ck-label">输入格式</label>
            <select v-model="keyConv.format" class="ck-select">
              <option value="auto">自动识别</option>
              <option value="pem">PEM</option>
              <option value="hex">Hex</option>
              <option value="base64">Base64</option>
            </select>
          </div>
          <CryptoPanel v-model="keyConv.data" label="密钥输入" type="textarea" :rows="3" clearable />
          <button @click="convertKey" class="ck-btn-primary w-full justify-center text-sm">
            <KeyIcon class="w-3.5 h-3.5" /> 转换
          </button>
          <div v-if="keyConvResult.error" class="text-xs text-red-400">{{ keyConvResult.error }}</div>
          <div v-if="keyConvResult.keyType" class="text-xs text-amber-400">类型: {{ keyConvResult.keyType }}</div>
        </div>

        <div class="ck-card space-y-3">
          <p class="ck-section-title">证书链验证</p>
          <CryptoPanel v-model="certChain.leaf" label="Leaf 证书 (PEM)" type="textarea" :rows="3" clearable />
          <CryptoPanel v-model="certChain.intermediates" label="中间证书 (PEM, 可选)" type="textarea" :rows="2" clearable />
          <CryptoPanel v-model="certChain.roots" label="根证书 (PEM, 可选)" type="textarea" :rows="2" clearable />
          <button @click="verifyChain" class="ck-btn-primary w-full justify-center text-sm">
            <ShieldCheckIcon class="w-3.5 h-3.5" /> 验证链
          </button>
          <div v-if="certChainResult.error" class="text-xs text-red-400">{{ certChainResult.error }}</div>
          <div v-if="certChainResult.data" class="text-xs text-emerald-400 whitespace-pre-line">{{ certChainResult.data }}</div>
        </div>

        <div class="ck-card space-y-3">
          <p class="ck-section-title">PKCS#12 (.pfx) 导入</p>
          <div class="flex gap-2">
            <button @click="uploadPfx" class="ck-btn-muted flex-1 text-xs justify-center">
              <FolderOpenIcon class="w-3.5 h-3.5" /> 选择 PFX 文件
            </button>
          </div>
          <label class="ck-label">密码</label>
          <input v-model="pfx.password" class="ck-input ck-trim-space" type="password" placeholder="PFX 密码" />
          <CryptoPanel v-model="pfx.data" label="PFX 数据 (Base64/Hex)" type="textarea" :rows="3" clearable />
          <div>
            <label class="ck-label">输入格式</label>
            <select v-model="pfx.format" class="ck-select">
              <option value="base64">Base64</option>
              <option value="hex">Hex</option>
            </select>
          </div>
          <button @click="parsePfx" class="ck-btn-primary w-full justify-center text-sm">解析</button>
          <div v-if="pfxResult.error" class="text-xs text-red-400">{{ pfxResult.error }}</div>
        </div>
      </div>

      <div class="ck-stack">
        <div class="ck-card">
          <label class="ck-label">PKCS#1 (PEM)</label>
          <textarea readonly class="ck-result ck-result-sm text-xs font-mono w-full min-h-[60px] resize-none bg-transparent outline-none border-none"
                    :value="keyConvResult.pkcs1"></textarea>
        </div>
        <div class="ck-card">
          <label class="ck-label">PKCS#8 (PEM)</label>
          <textarea readonly class="ck-result ck-result-sm text-xs font-mono w-full min-h-[60px] resize-none bg-transparent outline-none border-none"
                    :value="keyConvResult.pkcs8"></textarea>
        </div>
        <div class="ck-card">
          <label class="ck-label">公钥 (PEM)</label>
          <textarea readonly class="ck-result ck-result-sm text-xs font-mono w-full min-h-[60px] resize-none bg-transparent outline-none border-none"
                    :value="keyConvResult.pub"></textarea>
        </div>
        <div class="ck-card">
          <label class="ck-label">DER (Hex/Base64)</label>
          <textarea readonly class="ck-result ck-result-sm text-xs font-mono w-full min-h-[50px] resize-none bg-transparent outline-none border-none"
                    :value="keyConvResult.derHex"></textarea>
          <textarea readonly class="ck-result ck-result-sm text-xs font-mono w-full min-h-[50px] resize-none bg-transparent outline-none border-none mt-2"
                    :value="keyConvResult.derBase64"></textarea>
        </div>
        <div class="ck-card">
          <label class="ck-label">PFX 导入结果</label>
          <textarea readonly class="ck-result ck-result-sm text-xs font-mono w-full min-h-[60px] resize-none bg-transparent outline-none border-none"
                    :value="pfxResult.key"></textarea>
          <textarea readonly class="ck-result ck-result-sm text-xs font-mono w-full min-h-[60px] resize-none bg-transparent outline-none border-none mt-2"
                    :value="pfxResult.cert"></textarea>
          <textarea readonly class="ck-result ck-result-sm text-xs font-mono w-full min-h-[60px] resize-none bg-transparent outline-none border-none mt-2"
                    :value="pfxResult.ca"></textarea>
          <div v-if="pfxResult.info" class="mt-1 text-xs text-amber-400">证书: {{ pfxResult.info }}</div>
        </div>
      </div>
    </div>

    <!-- Packet I/O -->
    <div v-if="activeTab === 'packet'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">报文发送 / 接收</p>
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="ck-label">主机地址</label>
              <input v-model="packet.host" class="ck-input" placeholder="127.0.0.1" />
            </div>
            <div>
              <label class="ck-label">端口</label>
              <input v-model.number="packet.port" type="number" min="1" max="65535" class="ck-input" placeholder="8000" />
            </div>
          </div>

          <div class="grid grid-cols-3 gap-2">
            <div>
              <label class="ck-label">网络模式</label>
              <select v-model="packet.network" class="ck-select">
                <option value="auto">auto (DNS/IPv4/IPv6)</option>
                <option value="tcp">tcp</option>
                <option value="tcp4">tcp4</option>
                <option value="tcp6">tcp6</option>
              </select>
            </div>
            <div>
              <label class="ck-label">传输模式</label>
              <select v-model="packet.transport" class="ck-select">
                <option value="plain">plain</option>
                <option value="tls">tls</option>
                <option value="tlcp">tlcp</option>
              </select>
            </div>
            <div>
              <label class="ck-label">ServerName（SNI）</label>
              <input v-model="packet.serverName" class="ck-input" placeholder="可选（仅 TLS/TLCP）" />
            </div>
          </div>

          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="ck-label">允许不验证证书</label>
              <div class="flex items-center gap-2 mt-1">
                <input type="checkbox" v-model="packet.insecureSkipVerify" id="insecureSkipVerify" />
                <label for="insecureSkipVerify" class="text-xs">InsecureSkipVerify</label>
              </div>
            </div>
          </div>

          <div v-if="packet.transport === 'tls' || packet.transport === 'tlcp'" class="grid grid-cols-1 gap-2">
            <label class="ck-label">CA 证书 (PEM)</label>
            <textarea v-model="packet.caCert" rows="3" class="ck-textarea" placeholder="粘贴或加载 CA PEM 证书"></textarea>
            <button @click="loadCertFile('caCert')" class="ck-btn-muted">加载 CA 证书文件</button>

            <label class="ck-label">客户端签名证书 (PEM)</label>
            <textarea v-model="packet.clientCert" rows="3" class="ck-textarea" placeholder="粘贴客户端签名证书"></textarea>
            <button @click="loadCertFile('clientCert')" class="ck-btn-muted">加载签名证书文件</button>

            <label class="ck-label">客户端签名私钥 (PEM)</label>
            <textarea v-model="packet.clientKey" rows="3" class="ck-textarea" placeholder="粘贴客户端签名私钥"></textarea>
            <button @click="loadCertFile('clientKey')" class="ck-btn-muted">加载签名私钥文件</button>
          </div>

          <div v-if="packet.transport === 'tlcp'" class="grid grid-cols-1 gap-2">
            <label class="ck-label">TLCP 加密证书 (PEM)</label>
            <textarea v-model="packet.clientEncCert" rows="3" class="ck-textarea" placeholder="粘贴 TLCP 加密证书"></textarea>
            <button @click="loadCertFile('clientEncCert')" class="ck-btn-muted">加载加密证书文件</button>

            <label class="ck-label">TLCP 加密私钥 (PEM)</label>
            <textarea v-model="packet.clientEncKey" rows="3" class="ck-textarea" placeholder="粘贴 TLCP 加密私钥"></textarea>
            <button @click="loadCertFile('clientEncKey')" class="ck-btn-muted">加载加密私钥文件</button>
          </div>

          <div class="grid grid-cols-3 gap-2">
            <div>
              <label class="ck-label">报文头长度</label>
              <select v-model.number="packet.headerLength" class="ck-select">
                <option :value="0">0 字节</option>
                <option :value="1">1 字节</option>
                <option :value="2">2 字节</option>
                <option :value="3">3 字节</option>
                <option :value="4">4 字节</option>
              </select>
            </div>
            <div>
              <label class="ck-label">发送格式</label>
              <select v-model="packet.payloadFormat" class="ck-select">
                <option value="hex">Hex</option>
                <option value="text">文本</option>
              </select>
            </div>
            <div>
              <label class="ck-label">响应显示</label>
              <select v-model="packet.responseFormat" class="ck-select">
                <option value="text">文本优先</option>
                <option value="hex">Hex</option>
              </select>
            </div>
          </div>

          <div class="grid grid-cols-[1fr_auto] gap-2 items-end">
            <div>
              <label class="ck-label">超时 (毫秒)</label>
              <input v-model.number="packet.timeoutMs" type="number" min="200" max="60000" step="100" class="ck-input" />
            </div>
            <button @click="choosePacketFile" class="ck-btn-muted justify-center whitespace-nowrap">
              <FolderOpenIcon class="w-3.5 h-3.5" /> 选择报文文件
            </button>
          </div>

          <div v-if="packet.filePath" class="packet-file-bar">
            <span class="truncate">{{ packet.filePath }}</span>
            <button @click="packet.filePath = ''" class="ck-copy-btn">移除文件</button>
          </div>

          <div class="packet-view-switch">
            <button class="ck-chip-btn" :class="{ active: packet.editorView === 'hex' }" @click="packet.editorView = 'hex'">Hex 视图</button>
            <button class="ck-chip-btn" :class="{ active: packet.editorView === 'text' }" @click="packet.editorView = 'text'">文本视图</button>
            <span v-if="packetSyncError" class="packet-sync-error">{{ packetSyncError }}</span>
          </div>

          <CryptoPanel
            v-if="packet.editorView === 'hex'"
            v-model="packet.payloadHex"
            label="发送报文 (Hex)"
            type="textarea"
            :rows="3"
            clearable
            placeholder="粘贴 Hex 报文，文本发送上限约 1MB，文件模式可发送更大内容..."
          />
          <CryptoPanel
            v-else
            v-model="packet.payloadText"
            label="发送报文 (文本)"
            type="textarea"
            :rows="3"
            clearable
            placeholder="输入待发送报文，Hex / 文本视图会自动同步..."
          />

          <div class="flex gap-2">
            <button @click="sendPacketNow" class="ck-btn-primary flex-1 justify-center">
              <ZapIcon class="w-3.5 h-3.5" /> 发送并接收
            </button>
            <button @click="resetPacket" class="ck-btn-secondary justify-center">清空</button>
          </div>

          <div class="packet-meta-grid">
            <div class="ck-note-card">
              <p class="ck-note-title text-amber-400">发送提示</p>
              <p>头长为 0 时直接发原始字节流；头长 1-4 时按大端长度前缀自动封包。</p>
            </div>
            <div class="ck-note-card">
              <p class="ck-note-title text-cyan-400">文件模式</p>
              <p>选择文件后优先发送文件内容，适合超过 1MB 的大报文测试，不影响当前整体布局。</p>
            </div>
          </div>
        </div>
      </div>

      <div class="ck-stack">
        <div class="ck-card space-y-2">
          <p class="ck-section-title">响应内容</p>
          <div class="packet-stats">
            <span class="packet-stat">发送 {{ packetResult.requestBytes || 0 }} B</span>
            <span class="packet-stat">接收 {{ packetResult.responseBytes || 0 }} B</span>
            <span class="packet-stat">{{ packetResult.durationMs || 0 }} ms</span>
          </div>
          <div class="packet-view-switch !mb-1">
            <button class="ck-chip-btn" :class="{ active: packet.responseView === 'text' }" @click="packet.responseView = 'text'">文本视图</button>
            <button class="ck-chip-btn" :class="{ active: packet.responseView === 'hex' }" @click="packet.responseView = 'hex'">Hex 视图</button>
          </div>
          <CryptoPanel :model-value="packetResponseDisplay" label="响应数据" type="result" :success="packetResult.success" copyable />
          <div v-if="packetResult.error" class="text-xs text-red-400">{{ packetResult.error }}</div>
        </div>

        <div class="ck-card space-y-2">
          <p class="ck-section-title">发送历史</p>
          <div v-if="!packetHistory.length" class="ck-empty py-4">最近发送的连接参数和报文会显示在这里。</div>
          <div v-else class="space-y-2 max-h-[260px] overflow-y-auto pr-1">
            <button v-for="entry in packetHistory" :key="entry.id" class="packet-history-item" @click="applyPacketHistory(entry)">
              <div class="flex items-center justify-between gap-2">
                <span class="font-semibold truncate">{{ entry.host }}:{{ entry.port }}</span>
                <span class="text-[10px] opacity-70">{{ entry.time }}</span>
              </div>
              <div class="text-[11px] opacity-80">头长 {{ entry.headerLength }} · {{ entry.payloadFormat.toUpperCase() }} · {{ entry.requestBytes }} B</div>
              <div class="text-[11px] font-mono truncate opacity-70">{{ entry.preview }}</div>
            </button>
          </div>
        </div>

        <div class="ck-card space-y-2">
          <p class="ck-section-title">响应 Hex / 报文头</p>
          <CryptoPanel v-model="packetResult.responseHex" label="响应 Hex" type="result" :success="packetResult.success" copyable compact />
          <CryptoPanel v-model="packetResult.headerHex" label="响应头 Hex" type="result" :success="packetResult.success" copyable compact />
          <div class="ck-note-card">
            <p class="ck-note-title text-violet-400">使用说明</p>
            <p class="text-[12px] leading-5" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">如果服务端返回的是二进制内容，界面会自动回退到 Hex 展示；文本协议则优先直接展示可读内容。</p>
          </div>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useRoute, useRouter } from 'vue-router'
import { WrenchIcon, ZapIcon, RefreshCwIcon, FolderOpenIcon, KeyIcon, ShieldCheckIcon } from 'lucide-vue-next'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import { HexToString, StringToHex, Base64Encode, Base64Decode, XORCompute, URLEncode, URLDecode, UnicodeEncode, UnicodeDecode, GenerateRandom, PaddingApply, PaddingRemove, BaseConvert, TimestampConvert, ParseASN1, ParseASN1File, Base32Encode, Base32Decode, Base58Encode, Base58Decode, Bech32Encode, Bech32Decode, ParseJWT, ConvertKey, VerifyCertChain, ParsePKCS12, ParsePKCS12File, SelectFile, ReadFile, SendPacket } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const route = useRoute()
const router = useRouter()
const { isDark } = storeToRefs(store)
const { addHistory, showToast } = store

const tabs = [
  { id: 'encode', label: '编解码' },
  { id: 'xor', label: 'XOR / 进制' },
  { id: 'random', label: '随机 / 填充' },
  { id: 'timestamp', label: '时间戳' },
  { id: 'asn1', label: 'ASN.1' },
  { id: 'base', label: 'BaseX' },
  { id: 'jwt', label: 'JWT/JWK' },
  { id: 'keycert', label: 'Key/Cert' },
  { id: 'packet', label: '报文收发' },
]
const visibleTabs = computed(() => route.path === '/packet' ? [{ id: 'packet', label: '报文收发' }] : tabs)
const pageTitle = computed(() => route.path === '/packet' ? '报文发送 / 接收' : '编解码工具箱')
const pageSubtitle = computed(() => route.path === '/packet' ? 'TCP 报文头长度 · Hex / 文本双视图 · 文件发送 · 发送历史' : '进制转换 · Base64 · XOR · 时间戳 · Key/Cert · 报文收发')
const activeTab = ref(route.path === '/packet' ? 'packet' : 'encode')

function syncTabFromRoute() {
  if (route.path === '/packet') {
    activeTab.value = 'packet'
    return
  }
  const tab = typeof route.query.tab === 'string' ? route.query.tab : ''
  activeTab.value = tabs.some(item => item.id === tab) ? tab : 'encode'
}

function handleTabChange(tabId) {
  activeTab.value = tabId
  if (tabId === 'packet') {
    router.replace({ path: '/packet' })
    return
  }
  if (route.path === '/packet') {
    router.replace({ path: '/tools', query: { tab: tabId } })
    return
  }
  router.replace({ path: '/tools', query: tabId === 'encode' ? {} : { tab: tabId } })
}

watch(() => [route.path, route.query.tab], syncTabFromRoute, { immediate: true })

// Encoding
const enc = reactive({ input: '' })
const b64 = reactive({ input: '', format: 'Standard', isHex: false })
const urlEnc = reactive({ input: '' })
const unicode = reactive({ input: '' })
const encResult = reactive({ data: '', error: '', success: null })

async function strToHex() {
  const r = await StringToHex(enc.input)
  encResult.data = r.data; encResult.error = r.error; encResult.success = r.success
}
async function hexToStr() {
  const r = await HexToString(enc.input)
  encResult.data = r.data; encResult.error = r.error; encResult.success = r.success
}
async function b64Encode() {
  const r = await Base64Encode({ data: b64.input, format: b64.format, isHex: b64.isHex })
  encResult.data = r.data; encResult.error = r.error; encResult.success = r.success
}
async function b64Decode() {
  const r = await Base64Decode({ data: b64.input, format: b64.format, isHex: b64.isHex })
  encResult.data = r.data; encResult.error = r.error; encResult.success = r.success
}
async function doUrlEncode() {
  const r = await URLEncode(urlEnc.input)
  encResult.data = r.data; encResult.success = r.success
}
async function doUrlDecode() {
  const r = await URLDecode(urlEnc.input)
  encResult.data = r.data; encResult.success = r.success
}
async function unicodeEnc() {
  const r = await UnicodeEncode(unicode.input)
  encResult.data = r.data; encResult.success = r.success
}
async function unicodeDec() {
  const r = await UnicodeDecode(unicode.input)
  encResult.data = r.data; encResult.success = r.success
}

// XOR
const xor = reactive({ a: '', b: '' })
const xorResult = reactive({ data: '', error: '', success: null })
const baseConv = reactive({ from: 10, to: 16, value: '' })

async function doXOR() {
  const r = await XORCompute(xor)
  xorResult.data = r.data; xorResult.error = r.error; xorResult.success = r.success
}
async function doBaseConvert() {
  const r = await BaseConvert(baseConv)
  xorResult.data = r.data; xorResult.error = r.error; xorResult.success = r.success
}

// Random
const rng = reactive({ length: 32, format: 'hex' })
const rngResult = reactive({ data: '', success: null })
const pad = reactive({ data: '', mode: 'PKCS7', blockSize: 16 })
const padResult = reactive({ data: '', error: '', success: null })
const xchacha = reactive({ key: '', nonce: '' })

async function doGenRandom() {
  const r = await GenerateRandom(rng)
  rngResult.data = r.data; rngResult.success = r.success
}
async function doPadApply() {
  const r = await PaddingApply(pad)
  padResult.data = r.data; padResult.error = r.error; padResult.success = r.success
}
async function doPadRemove() {
  const r = await PaddingRemove(pad)
  padResult.data = r.data; padResult.error = r.error; padResult.success = r.success
}

function genXChaCha() {
  const key = new Uint8Array(32); crypto.getRandomValues(key)
  const nonce = new Uint8Array(24); crypto.getRandomValues(nonce)
  xchacha.key = Array.from(key).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
  xchacha.nonce = Array.from(nonce).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()
}

// Timestamp
const ts = reactive({ value: '', from: 'unix10', to: 'datetime', timezone: 'Asia/Shanghai' })
const tsResult = reactive({ data: '', error: '', success: null })
const nowUnix = ref(Math.floor(Date.now() / 1000))
const nowUnixMs = ref(Date.now())
const nowUTC = ref(new Date().toUTCString())

const tsPlaceholder = computed(() => {
  const map = { unix10: '如: 1700000000', unix13: '如: 1700000000000', rfc3339: '如: 2024-01-01T00:00:00Z', datetime: '如: 2024-01-01 12:00:00' }
  return map[ts.from] || ''
})

let timer
onMounted(() => { timer = setInterval(() => { nowUnix.value = Math.floor(Date.now()/1000); nowUnixMs.value = Date.now(); nowUTC.value = new Date().toUTCString() }, 1000) })
onUnmounted(() => clearInterval(timer))

async function doTsConvert() {
  const r = await TimestampConvert(ts)
  tsResult.data = r.data; tsResult.error = r.error; tsResult.success = r.success
}
function nowTs() {
  if (ts.from === 'unix10') ts.value = String(Math.floor(Date.now()/1000))
  else if (ts.from === 'unix13') ts.value = String(Date.now())
  else if (ts.from === 'rfc3339') ts.value = new Date().toISOString()
  else ts.value = new Date().toLocaleString('sv-SE').replace('T', ' ')
}

// ASN.1
const asn1 = reactive({ input: '', format: 'auto' })
const asn1Result = reactive({ data: '', error: '', success: null })

async function parseAsn1() {
  const r = await ParseASN1(asn1)
  asn1Result.data = r.data; asn1Result.error = r.error; asn1Result.success = r.success
}

async function uploadAsn1File() {
  const path = await SelectFile()
  if (!path) return
  const r = await ParseASN1File(path)
  asn1Result.data = r.data; asn1Result.error = r.error; asn1Result.success = r.success
}

// BaseX
const b32 = reactive({ input: '', format: 'Standard', isHex: false, noPadding: false })
const b58 = reactive({ input: '', isHex: false })
const bech = reactive({ hrp: 'bc', input: '', isHex: true, decoded: '' })
const baseResult = reactive({ data: '', error: '', success: null })

async function doBase32Encode() {
  const r = await Base32Encode({ data: b32.input, variant: b32.format, isHex: b32.isHex, noPadding: b32.noPadding })
  baseResult.data = r.data; baseResult.error = r.error; baseResult.success = r.success
}
async function doBase32Decode() {
  const r = await Base32Decode({ data: b32.input, variant: b32.format, isHex: b32.isHex, noPadding: b32.noPadding })
  baseResult.data = r.data; baseResult.error = r.error; baseResult.success = r.success
}
async function doBase58Encode() {
  const r = await Base58Encode({ data: b58.input, isHex: b58.isHex })
  baseResult.data = r.data; baseResult.error = r.error; baseResult.success = r.success
}
async function doBase58Decode() {
  const r = await Base58Decode({ data: b58.input, isHex: b58.isHex })
  baseResult.data = r.data; baseResult.error = r.error; baseResult.success = r.success
}
async function doBech32Encode() {
  const r = await Bech32Encode({ hrp: bech.hrp, data: bech.input, isHex: bech.isHex })
  baseResult.data = r.data; baseResult.error = r.error; baseResult.success = r.success
}
async function doBech32Decode() {
  const r = await Bech32Decode(bech.decoded)
  baseResult.data = r.data ? `HRP=${r.hrp}\nDATA=${r.data}` : ''
  baseResult.error = r.error; baseResult.success = r.success
}

// JWT/JWK
const jwt = reactive({ token: '', key: '', keyFormat: 'auto', verify: false })
const jwtResult = reactive({ header: '', payload: '', valid: false, error: '' })

async function parseJwt() {
  const r = await ParseJWT(jwt)
  jwtResult.header = r.header || ''
  jwtResult.payload = r.payload || ''
  jwtResult.valid = r.valid
  jwtResult.error = r.error || ''
}

// Key/Cert
const keyConv = reactive({ data: '', format: 'auto' })
const keyConvResult = reactive({ pkcs1: '', pkcs8: '', pub: '', derHex: '', derBase64: '', error: '', keyType: '' })

async function convertKey() {
  const r = await ConvertKey(keyConv)
  keyConvResult.pkcs1 = r.pkcs1Pem; keyConvResult.pkcs8 = r.pkcs8Pem
  keyConvResult.pub = r.publicPem; keyConvResult.derHex = r.derHex
  keyConvResult.derBase64 = r.derBase64; keyConvResult.error = r.error
  keyConvResult.keyType = r.keyType
}

const certChain = reactive({ leaf: '', intermediates: '', roots: '' })
const certChainResult = reactive({ data: '', error: '', valid: false })

async function verifyChain() {
  const r = await VerifyCertChain(certChain)
  certChainResult.data = r.data; certChainResult.error = r.error; certChainResult.valid = r.valid
}

const pfx = reactive({ data: '', format: 'base64', password: '' })
const pfxResult = reactive({ key: '', cert: '', ca: '', info: '', error: '' })

async function parsePfx() {
  const r = await ParsePKCS12(pfx)
  pfxResult.key = r.keyPem; pfxResult.cert = r.certPem; pfxResult.ca = r.caPem; pfxResult.info = r.certInfo
  pfxResult.error = r.error
}

async function uploadPfx() {
  const path = await SelectFile()
  if (!path) return
  const r = await ParsePKCS12File(path, pfx.password)
  pfxResult.key = r.keyPem; pfxResult.cert = r.certPem; pfxResult.ca = r.caPem; pfxResult.info = r.certInfo
  pfxResult.error = r.error
}

const PACKET_PREFS_KEY = 'ck-packet-prefs'
const PACKET_HISTORY_KEY = 'ck-packet-history'
const packet = reactive({
  host: '127.0.0.1',
  port: 8000,
  headerLength: 4,
  timeoutMs: 5000,
  payloadText: '',
  payloadHex: '',
  payloadFormat: 'hex',
  responseFormat: 'text',
  filePath: '',
  editorView: 'hex',
  responseView: 'text',
  network: 'auto',
  transport: 'plain',
  serverName: '',
  insecureSkipVerify: false,
  caCert: '',
  clientCert: '',
  clientKey: '',
  clientEncCert: '',
  clientEncKey: '',
})
const packetResult = reactive({
  success: null,
  error: '',
  response: '',
  responseHex: '',
  requestBytes: 0,
  responseBytes: 0,
  headerHex: '',
  durationMs: 0,
})
const packetHistory = ref([])
const packetSyncError = ref('')
let packetSyncLock = false

function textToHex(text) {
  return Array.from(new TextEncoder().encode(text)).map(byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase()
}

function hexToText(hex) {
  const clean = hex.replace(/\s+/g, '')
  if (!clean) return ''
  if (clean.length % 2 !== 0) throw new Error('Hex 长度必须为偶数')
  if (!/^[0-9a-fA-F]+$/.test(clean)) throw new Error('Hex 中包含非法字符')
  return new TextDecoder().decode(Uint8Array.from(clean.match(/.{2}/g).map(v => parseInt(v, 16))))
}

const packetResponseDisplay = computed(() => packet.responseView === 'hex' ? (packetResult.responseHex || packetResult.response) : (packetResult.response || packetResult.responseHex))

function savePacketPrefs() {
  localStorage.setItem(PACKET_PREFS_KEY, JSON.stringify({
    host: packet.host,
    port: packet.port,
    headerLength: packet.headerLength,
    timeoutMs: packet.timeoutMs,
    payloadFormat: packet.payloadFormat,
    responseFormat: packet.responseFormat,
    editorView: packet.editorView,
    responseView: packet.responseView,
    network: packet.network,
    transport: packet.transport,
    serverName: packet.serverName,
    insecureSkipVerify: packet.insecureSkipVerify,
    caCert: packet.caCert,
    clientCert: packet.clientCert,
    clientKey: packet.clientKey,
    clientEncCert: packet.clientEncCert,
    clientEncKey: packet.clientEncKey,
  }))
}

function loadPacketPrefs() {
  try {
    const saved = JSON.parse(localStorage.getItem(PACKET_PREFS_KEY) || 'null')
    if (!saved) return
    packet.host = saved.host || packet.host
    packet.port = Number(saved.port) || packet.port
    packet.headerLength = Number.isInteger(saved.headerLength) ? saved.headerLength : packet.headerLength
    packet.timeoutMs = Number(saved.timeoutMs) || packet.timeoutMs
    packet.payloadFormat = saved.payloadFormat || packet.payloadFormat
    packet.responseFormat = saved.responseFormat || packet.responseFormat
    packet.editorView = saved.editorView || packet.editorView
    packet.responseView = saved.responseView || packet.responseView
    packet.network = saved.network || packet.network
    packet.transport = saved.transport || packet.transport
    packet.serverName = saved.serverName || packet.serverName
    packet.insecureSkipVerify = saved.insecureSkipVerify === true
    packet.caCert = saved.caCert || packet.caCert
    packet.clientCert = saved.clientCert || packet.clientCert
    packet.clientKey = saved.clientKey || packet.clientKey
    packet.clientEncCert = saved.clientEncCert || packet.clientEncCert
    packet.clientEncKey = saved.clientEncKey || packet.clientEncKey
  } catch {}
}

function loadPacketHistory() {
  try {
    packetHistory.value = JSON.parse(localStorage.getItem(PACKET_HISTORY_KEY) || '[]')
  } catch {
    packetHistory.value = []
  }
}

function persistPacketHistory() {
  localStorage.setItem(PACKET_HISTORY_KEY, JSON.stringify(packetHistory.value.slice(0, 12)))
}

function syncPacketTextToHex() {
  if (packetSyncLock) return
  packetSyncLock = true
  packetSyncError.value = ''
  packet.payloadHex = textToHex(packet.payloadText)
  packetSyncLock = false
}

function syncPacketHexToText() {
  if (packetSyncLock) return
  packetSyncLock = true
  try {
    packet.payloadText = hexToText(packet.payloadHex)
    packetSyncError.value = ''
  } catch (err) {
    packetSyncError.value = err.message
  }
  packetSyncLock = false
}

watch(() => packet.payloadText, syncPacketTextToHex)
watch(() => packet.payloadHex, syncPacketHexToText)
watch(() => [packet.host, packet.port, packet.headerLength, packet.timeoutMs, packet.payloadFormat, packet.responseFormat, packet.editorView, packet.responseView], savePacketPrefs, { deep: true })
watch(() => packet.payloadFormat, (format) => {
  packet.editorView = format === 'hex' ? 'hex' : 'text'
})

async function choosePacketFile() {
  const path = await SelectFile()
  if (path) packet.filePath = path
}

async function loadCertFile(field) {
  const path = await SelectFile()
  if (!path) return
  const content = await ReadFile(path)
  if (content) {
    packet[field] = content
    showToast('证书加载成功', 'success')
  } else {
    showToast('证书加载失败，请确认文件内容', 'error')
  }
}

async function sendPacketNow() {
  const payload = packet.payloadFormat === 'hex' ? packet.payloadHex : packet.payloadText
  const r = await SendPacket({
    host: packet.host,
    port: packet.port,
    network: packet.network,
    transport: packet.transport,
    serverName: packet.serverName,
    insecureSkipVerify: packet.insecureSkipVerify,
    headerLength: packet.headerLength,
    timeoutMs: packet.timeoutMs,
    payloadFormat: packet.payloadFormat,
    payload,
    responseFormat: packet.responseFormat,
    filePath: packet.filePath,
    caCertPem: packet.caCert,
    clientCertPem: packet.clientCert,
    clientKeyPem: packet.clientKey,
    clientEncCertPem: packet.clientEncCert,
    clientEncKeyPem: packet.clientEncKey,
  })
  packetResult.success = r.success
  packetResult.error = r.error || ''
  packetResult.response = r.response || ''
  packetResult.responseHex = r.responseHex || ''
  packetResult.requestBytes = r.requestBytes || 0
  packetResult.responseBytes = r.responseBytes || 0
  packetResult.headerHex = r.headerHex || ''
  packetResult.durationMs = r.durationMs || 0
  addHistory({
    type: '报文收发',
    data: `${packet.host}:${packet.port} ${packet.payloadFormat.toUpperCase()} ${packetResult.requestBytes}B`,
  })
  packetHistory.value.unshift({
    id: Date.now(),
    host: packet.host,
    port: packet.port,
    network: packet.network,
    transport: packet.transport,
    serverName: packet.serverName,
    insecureSkipVerify: packet.insecureSkipVerify,
    caCert: packet.caCert,
    clientCert: packet.clientCert,
    clientKey: packet.clientKey,
    clientEncCert: packet.clientEncCert,
    clientEncKey: packet.clientEncKey,
    headerLength: packet.headerLength,
    timeoutMs: packet.timeoutMs,
    payloadFormat: packet.payloadFormat,
    responseFormat: packet.responseFormat,
    payloadHex: packet.payloadHex,
    payloadText: packet.payloadText,
    filePath: packet.filePath,
    requestBytes: packetResult.requestBytes,
    time: new Date().toLocaleTimeString(),
    preview: (packet.payloadFormat === 'hex' ? packet.payloadHex : packet.payloadText).slice(0, 80),
  })
  packetHistory.value = packetHistory.value.slice(0, 12)
  persistPacketHistory()
  showToast(r.success ? '报文已发送' : '发送失败', r.success ? 'success' : 'error')
}

function applyPacketHistory(entry) {
  packet.host = entry.host
  packet.port = entry.port
  packet.headerLength = entry.headerLength
  packet.timeoutMs = entry.timeoutMs
  packet.payloadFormat = entry.payloadFormat
  packet.responseFormat = entry.responseFormat || packet.responseFormat
  packet.network = entry.network || packet.network
  packet.transport = entry.transport || packet.transport
  packet.serverName = entry.serverName || packet.serverName
  packet.insecureSkipVerify = entry.insecureSkipVerify || packet.insecureSkipVerify
  packet.caCert = entry.caCert || packet.caCert
  packet.clientCert = entry.clientCert || packet.clientCert
  packet.clientKey = entry.clientKey || packet.clientKey
  packet.clientEncCert = entry.clientEncCert || packet.clientEncCert
  packet.clientEncKey = entry.clientEncKey || packet.clientEncKey
  packet.filePath = entry.filePath || ''
  packet.payloadHex = entry.payloadHex || ''
  packet.payloadText = entry.payloadText || ''
  packet.editorView = entry.payloadFormat === 'hex' ? 'hex' : 'text'
  showToast('已载入历史参数')
}

function resetPacket() {
  packet.payloadText = ''
  packet.payloadHex = ''
  packet.filePath = ''
  packetResult.success = null
  packetResult.error = ''
  packetResult.response = ''
  packetResult.responseHex = ''
  packetResult.requestBytes = 0
  packetResult.responseBytes = 0
  packetResult.headerHex = ''
  packetResult.durationMs = 0
  packetSyncError.value = ''
}

onMounted(() => {
  loadPacketPrefs()
  loadPacketHistory()
})
</script>
