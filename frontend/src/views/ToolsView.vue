<template>
  <PageLayout :title="pageTitle" :subtitle="pageSubtitle"
              icon-bg="bg-amber-500/20"
              :tabs="visibleTabs" :active-tab="activeTab" @tab-change="handleTabChange">
    <template #icon>
      <WrenchIcon class="w-4 h-4 text-orange-300" />
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
      :icon="ShieldCheckIcon"
      @close="showPrinciple = false"
    >
      <div v-for="(section, idx) in parsedPrinciples" :key="idx">
        <h4>{{ section.title }}</h4>
        <p v-for="(line, lIdx) in section.content" :key="lIdx" class="principle-line">
          {{ line }}
        </p>
      </div>
    </AlgorithmDrawer>

    <!-- Encoding -->
    <div v-if="activeTab === 'encode'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <!-- Str <-> Hex -->
        <Card title="ASCII / 文本 ↔ Hex">
          <CryptoPanel v-model="enc.input" label="输入" type="textarea" :rows="3" clearable trim-hex-spaces placeholder="输入文本或hex（粘贴带空格的hex会自动去空格）..." />
          <div class="flex gap-2 mt-2">
            <Button variant="success" class="flex-1 justify-center text-xs" @click="strToHex">文本 → Hex</Button>
            <Button variant="warning" class="flex-1 justify-center text-xs" @click="hexToStr">Hex → 文本</Button>
          </div>
        </Card>

        <!-- Base64 -->
        <Card title="Base64">
          <div class="grid grid-cols-2 gap-2 mb-2">
            <div>
              <label class="input-label">编码标准</label>
              <Dropdown
                v-model="b64.format"
                :options="[
                  { value: 'Standard', label: 'Standard' },
                  { value: 'URL', label: 'URL安全' },
                  { value: 'NoPadding', label: '无填充' }
                ]"
              />
            </div>
            <div>
              <label class="input-label">输入格式</label>
              <Dropdown
                v-model="b64.isHex"
                :options="[
                  { value: 'false', label: '文本' },
                  { value: 'true', label: 'Hex' }
                ]"
              />
            </div>
          </div>
          <CryptoPanel v-model="b64.input" label="输入" type="textarea" :rows="3" clearable trim-hex-spaces />
          <div class="flex gap-2 mt-2">
            <Button variant="success" class="flex-1 justify-center text-xs" @click="b64Encode">编码</Button>
            <Button variant="warning" class="flex-1 justify-center text-xs" @click="b64Decode">解码</Button>
          </div>
        </Card>
      </div>

      <div class="sym-side">
        <!-- URL Encode -->
        <Card title="URL 编解码">
          <p class="text-[11px] mb-2" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">把特殊字符（空格、中文等）转成 %XX 百分号编码，用于 URL 参数 / 表单传输</p>
          <CryptoPanel v-model="urlEnc.input" label="输入" type="textarea" :rows="3" clearable />
          <div class="flex gap-2 mt-2">
            <Button variant="success" class="flex-1 justify-center text-xs" @click="doUrlEncode">URL编码</Button>
            <Button variant="warning" class="flex-1 justify-center text-xs" @click="doUrlDecode">URL解码</Button>
          </div>
        </Card>

        <!-- Unicode -->
        <Card title="Unicode 转义">
          <p class="text-[11px] mb-2" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">把中文/特殊字符转成 \uXXXX 转义序列，常用于 JSON 字符串、源码内嵌</p>
          <CryptoPanel v-model="unicode.input" label="输入" type="textarea" :rows="3" clearable />
          <div class="flex gap-2 mt-2">
            <Button variant="success" class="flex-1 justify-center text-xs" @click="unicodeEnc">编码 (\u转义)</Button>
            <Button variant="warning" class="flex-1 justify-center text-xs" @click="unicodeDec">解码</Button>
          </div>
        </Card>

        <!-- Result -->
        <Card title="编码结果">
          <ResultArea
            :modelValue="encResult.data"
            :error="encResult.error"
            :success="encResult.success"
            label="结果"
            copyable
          />
        </Card>
      </div>
    </div>

    <!-- XOR / Bitwise -->
    <div v-if="activeTab === 'xor'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="XOR 异或运算" class="space-y-3">
          <div>
            <Input v-model="xor.a" label="操作数 A (hex)" class="font-mono" placeholder="hex格式..." />
          </div>
          <div>
            <Input v-model="xor.b" label="操作数 B (hex)" class="font-mono" placeholder="hex格式..." />
          </div>
          <Button variant="primary" block @click="doXOR">
            <ZapIcon class="w-3.5 h-3.5" /> A ⊕ B
          </Button>
        </Card>

        <!-- Base convert -->
        <Card title="进制转换" class="space-y-3">
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="input-label">源进制</label>
              <Dropdown
                v-model="baseConv.from"
                :options="[
                  { value: '2', label: '二进制' },
                  { value: '8', label: '八进制' },
                  { value: '10', label: '十进制' },
                  { value: '16', label: '十六进制' }
                ]"
              />
            </div>
            <div>
              <label class="input-label">目标进制</label>
              <Dropdown
                v-model="baseConv.to"
                :options="[
                  { value: '2', label: '二进制' },
                  { value: '8', label: '八进制' },
                  { value: '10', label: '十进制' },
                  { value: '16', label: '十六进制' }
                ]"
              />
            </div>
          </div>
          <Input v-model="baseConv.value" class="font-mono" placeholder="输入数值..." />
          <Button variant="primary" block class="text-sm" @click="doBaseConvert">转换</Button>
        </Card>
      </div>

      <div class="sym-side">
        <Card title="XOR 结果">
          <ResultArea
            :modelValue="xorResult.data"
            :error="xorResult.error"
            :success="xorResult.success"
            label="运算结果"
            copyable
          />
        </Card>
      </div>
    </div>

    <!-- Random -->
    <div v-if="activeTab === 'random'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="随机数生成" class="space-y-3">
          <div>
              <label class="input-label">字节长度</label>
              <div class="flex gap-2 flex-wrap mb-2">
              <button v-for="n in [8, 16, 24, 32, 48, 64]" :key="n"
                      class="btn-tool"
                      :class="{ active: rng.length === n }"
                      @click="rng.length = n">{{ n }}B</button>
            </div>
            <Input v-model.number="rng.length" type="number" min="1" max="4096" />
          </div>
          <div>
            <label class="input-label">输出格式</label>
            <Dropdown
              v-model="rng.format"
              :options="[
                { value: 'hex', label: 'Hex' },
                { value: 'base64', label: 'Base64' }
              ]"
            />
          </div>
          <Button variant="primary" block @click="doGenRandom">
            <RefreshCwIcon class="w-3.5 h-3.5" /> 生成随机数
          </Button>
        </Card>

        <Card title="随机数结果">
          <ResultArea
            :modelValue="rngResult.data"
            :error="rngResult.error"
            :success="rngResult.success"
            label="随机数结果"
            copyable
          />
        </Card>

        <Card title="XChaCha20-Poly1305 Key/Nonce" class="space-y-3">
          <div>
            <label class="input-label">Key (32字节)</label>
            <div class="relative">
              <div class="result-area result-area-sm !min-h-0 pb-7 text-xs font-mono break-all">{{ xchacha.key }}</div>
              <ByteBadge :model-value="xchacha.key" />
            </div>
          </div>
          <div>
            <label class="input-label">Nonce (24字节)</label>
            <div class="relative">
              <div class="result-area result-area-sm !min-h-0 pb-7 text-xs font-mono break-all">{{ xchacha.nonce }}</div>
              <ByteBadge :model-value="xchacha.nonce" />
            </div>
          </div>
          <Button variant="tool" block class="text-sm" @click="genXChaCha">生成 Key / Nonce</Button>
        </Card>
      </div>

      <div class="sym-side">
        <Card title="数据填充工具" class="space-y-3">
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="input-label">填充模式</label>
              <Dropdown
                v-model="pad.mode"
                :options="[
                  { value: 'PKCS7', label: 'PKCS7' },
                  { value: 'PKCS5', label: 'PKCS5' },
                  { value: 'Zero', label: 'Zero' },
                  { value: 'ISO10126', label: 'ISO10126' },
                  { value: 'ANSIX923', label: 'ANSIX923' }
                ]"
              />
            </div>
            <div>
              <label class="input-label">块大小</label>
              <Dropdown
                v-model="pad.blockSize"
                :options="[
                  { value: '8', label: '8字节(DES)' },
                  { value: '16', label: '16字节(AES)' }
                ]"
              />
            </div>
          </div>
          <CryptoPanel v-model="pad.data" label="数据 (hex)" type="input" clearable />
          <div class="flex gap-2">
            <Button variant="success" class="flex-1 text-xs justify-center" @click="doPadApply">添加填充</Button>
            <Button variant="warning" class="flex-1 text-xs justify-center" @click="doPadRemove">移除填充</Button>
          </div>
        </Card>
        <Card title="填充结果">
          <ResultArea
            :modelValue="padResult.data"
            :error="padResult.error"
            :success="padResult.success"
            label="填充结果 (hex)"
            copyable
          />
        </Card>
        <Card title="填充说明">
          <div class="space-y-2 text-[12px] leading-5" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="card">
              <p class="card-title text-violet-400">常见块长</p>
              <p>DES / 3DES 通常用 8 字节块长，AES / SM4 通常用 16 字节块长。</p>
            </div>
            <div class="card">
              <p class="card-title text-orange-300">联调提醒</p>
              <p>移除填充失败时，通常是块长、模式或输入编码和对端不一致。</p>
            </div>
          </div>
        </Card>
      </div>
    </div>

    <!-- Timestamp -->
    <div v-if="activeTab === 'timestamp'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="时间戳转换" class="space-y-3">
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="input-label">输入格式</label>
              <Dropdown
                v-model="ts.from"
                :options="[
                  { value: 'unix10', label: 'Unix (秒)' },
                  { value: 'unix13', label: 'Unix (毫秒)' },
                  { value: 'rfc3339', label: 'RFC3339' },
                  { value: 'datetime', label: '日期时间' }
                ]"
              />
            </div>
            <div>
              <label class="input-label">输出格式</label>
              <Dropdown
                v-model="ts.to"
                :options="[
                  { value: 'unix10', label: 'Unix (秒)' },
                  { value: 'unix13', label: 'Unix (毫秒)' },
                  { value: 'rfc3339', label: 'RFC3339' },
                  { value: 'datetime', label: '日期时间' }
                ]"
              />
            </div>
          </div>
          <div>
            <label class="input-label">时区</label>
            <Dropdown
              v-model="ts.timezone"
              :options="[
                { value: 'Asia/Shanghai', label: 'Asia/Shanghai (UTC+8)' },
                { value: 'UTC', label: 'UTC' },
                { value: 'America/New_York', label: 'America/New_York' },
                { value: 'Europe/London', label: 'Europe/London' },
                { value: 'Asia/Tokyo', label: 'Asia/Tokyo' }
              ]"
            />
          </div>
          <Input v-model="ts.value" class="font-mono" :placeholder="tsPlaceholder" />
          <div class="flex gap-2">
            <Button variant="primary" class="flex-1 justify-center text-sm" @click="doTsConvert">转换</Button>
            <Button variant="tool" class="text-xs" @click="nowTs">当前时间</Button>
          </div>
        </Card>
      </div>
      <div class="sym-side">
        <Card title="转换结果">
          <ResultArea
            :modelValue="tsResult.data"
            :error="tsResult.error"
            :success="tsResult.success"
            label="转换结果"
            copyable
          />
        </Card>
        <!-- Quick ref -->
        <Card title="快速参考">
          <div class="space-y-1.5 text-sm" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="flex justify-between">
              <span class="text-[13px]">当前Unix(秒):</span>
              <span class="font-mono text-[13px]" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ nowUnix }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-[13px]">当前Unix(毫秒):</span>
              <span class="font-mono text-[13px]" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ nowUnixMs }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-[13px]">UTC时间:</span>
              <span class="font-mono text-[13px]" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ nowUTC }}</span>
            </div>
          </div>
        </Card>
      </div>
    </div>

    <!-- ASN.1 -->
    <div v-if="activeTab === 'asn1'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="ASN.1 解析" class="space-y-3">
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="input-label">输入格式</label>
              <Dropdown
                v-model="asn1.format"
                :options="[
                  { value: 'auto', label: '自动识别' },
                  { value: 'pem', label: 'PEM' },
                  { value: 'hex', label: 'Hex' },
                  { value: 'base64', label: 'Base64' },
                  { value: 'text', label: '文本' }
                ]"
              />
            </div>
            <div class="flex items-end">
              <Button variant="tool" block class="text-xs" @click="uploadAsn1File">
                <FolderOpenIcon class="w-3.5 h-3.5" /> 选择文件解析
              </Button>
            </div>
          </div>
          <CryptoPanel v-model="asn1.input" label="输入 (可粘贴 PEM/DER/Hex/Base64)" type="textarea" :rows="3" clearable />
          <Button variant="primary" block class="text-sm" @click="parseAsn1">解析</Button>
        </Card>
      </div>

      <div class="sym-side">
        <Card title="解析结果">
          <ResultArea
            :modelValue="asn1Result.data"
            :error="asn1Result.error"
            label="解析结果"
            placeholder="结果将显示在这里..."
          />
        </Card>
      </div>
    </div>

    <!-- BaseX -->
    <div v-if="activeTab === 'base'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="Base32" class="space-y-3">
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="input-label">字母表</label>
              <Dropdown
                v-model="b32.format"
                :options="[
                  { value: 'Standard', label: 'Standard' },
                  { value: 'Hex', label: 'Hex' }
                ]"
              />
            </div>
            <div>
              <label class="input-label">输入格式</label>
              <Dropdown
                v-model="b32.isHex"
                :options="[
                  { value: 'false', label: '文本' },
                  { value: 'true', label: 'Hex' }
                ]"
              />
            </div>
          </div>
          <label class="input-label">
            <input v-model="b32.noPadding" type="checkbox" class="mr-2">不使用填充
          </label>
          <CryptoPanel v-model="b32.input" label="输入" type="textarea" :rows="3" clearable />
          <div class="flex gap-2">
            <Button variant="success" class="flex-1 text-xs justify-center" @click="doBase32Encode">编码</Button>
            <Button variant="warning" class="flex-1 text-xs justify-center" @click="doBase32Decode">解码</Button>
          </div>
        </Card>

        <Card title="Base58" class="space-y-3">
          <div>
            <label class="input-label">输入格式</label>
            <Dropdown
              v-model="b58.isHex"
              :options="[
                { value: 'false', label: '文本' },
                { value: 'true', label: 'Hex' }
              ]"
            />
          </div>
          <CryptoPanel v-model="b58.input" label="输入" type="textarea" :rows="3" clearable />
          <div class="flex gap-2">
            <Button variant="success" class="flex-1 text-xs justify-center" @click="doBase58Encode">编码</Button>
            <Button variant="warning" class="flex-1 text-xs justify-center" @click="doBase58Decode">解码</Button>
          </div>
        </Card>

        <Card title="Bech32" class="space-y-3">
          <div class="grid grid-cols-2 gap-2">
            <div>
              <Input v-model="bech.hrp" label="HRP" class="font-mono" />
            </div>
            <div>
              <label class="input-label">输入格式</label>
              <Dropdown
                v-model="bech.isHex"
                :options="[
                  { value: 'true', label: 'Hex' },
                  { value: 'false', label: '文本' }
                ]"
              />
            </div>
          </div>
          <CryptoPanel v-model="bech.input" label="编码输入" type="textarea" :rows="2" clearable />
          <Button variant="success" block class="text-xs" @click="doBech32Encode">编码</Button>
          <CryptoPanel v-model="bech.decoded" label="待解码 Bech32" type="textarea" :rows="2" clearable />
          <Button variant="warning" block class="text-xs" @click="doBech32Decode">解码</Button>
        </Card>
      </div>

      <div class="sym-side">
        <Card title="BaseX 结果">
          <ResultArea
            :modelValue="baseResult.data"
            :error="baseResult.error"
            :success="baseResult.success"
            label="结果"
            copyable
          />
        </Card>
        <Card title="说明">
          <div class="text-sm space-y-2" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <div class="p-2.5 rounded-lg border border-blue-500/10" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
              <p class="font-semibold text-blue-400 mb-1 text-[13px]">常见用途</p>
              <p class="text-[13px]">• Base32/58: 地址、序列号、短码。</p>
              <p class="text-[13px]">• Bech32: 地址编码 (如 BTC SegWit)。</p>
            </div>
          </div>
        </Card>
      </div>
    </div>

    <!-- JWT/JWK -->
    <div v-if="activeTab === 'jwt'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="JWT 解析/验证" class="space-y-3">
          <CryptoPanel v-model="jwt.token" label="JWT Token" type="textarea" :rows="3" clearable />
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="input-label">密钥格式</label>
              <Dropdown
                v-model="jwt.keyFormat"
                :options="[
                  { value: 'auto', label: '自动识别' },
                  { value: 'pem', label: 'PEM' },
                  { value: 'jwk', label: 'JWK/JWKS' },
                  { value: 'raw', label: '原始文本' }
                ]"
              />
            </div>
            <label class="input-label flex items-center gap-2 mt-5">
              <input v-model="jwt.verify" type="checkbox">验证签名
            </label>
          </div>
          <CryptoPanel v-model="jwt.key" label="密钥 (PEM/JWK/RAW)" type="textarea" :rows="3" clearable />
          <Button variant="primary" block class="text-sm" @click="parseJwt">解析 / 验证</Button>
        </Card>
      </div>
      <div class="sym-side">
        <Card title="Header">
          <textarea readonly class="result-area result-area-sm text-xs font-mono w-full min-h-[72px] resize-none bg-transparent outline-none border-none"
                    :value="jwtResult.header"></textarea>
        </Card>
        <Card title="Payload">
          <textarea readonly class="result-area result-area-sm text-xs font-mono w-full min-h-[72px] resize-none bg-transparent outline-none border-none"
                    :value="jwtResult.payload"></textarea>
          <div v-if="jwt.verify" class="mt-2 text-xs" :class="jwtResult.valid ? 'text-emerald-400' : 'text-red-400'">
            {{ jwtResult.valid ? '签名验证通过' : '签名验证失败' }}
          </div>
          <div v-if="jwtResult.error" class="mt-1 text-xs text-red-400">{{ jwtResult.error }}</div>
        </Card>
      </div>
    </div>

    <!-- Key/Cert -->
    <div v-if="activeTab === 'keycert'" class="sym-workbench animate-fade-in">
      <div class="sym-side">
        <Card title="密钥格式转换" class="space-y-3">
          <div>
            <label class="input-label">输入格式</label>
            <Dropdown
              v-model="keyConv.format"
              :options="[
                { value: 'auto', label: '自动识别' },
                { value: 'pem', label: 'PEM' },
                { value: 'hex', label: 'Hex' },
                { value: 'base64', label: 'Base64' }
              ]"
            />
          </div>
          <CryptoPanel v-model="keyConv.data" label="密钥输入" type="textarea" :rows="3" clearable />
          <Button variant="primary" block class="text-sm" @click="convertKey">
            <KeyIcon class="w-3.5 h-3.5" /> 转换
          </Button>
          <div v-if="keyConvResult.error" class="text-xs text-red-400">{{ keyConvResult.error }}</div>
          <div v-if="keyConvResult.keyType" class="text-xs text-orange-300">类型: {{ keyConvResult.keyType }}</div>
        </Card>

        <Card title="证书链验证" class="space-y-3">
          <CryptoPanel v-model="certChain.leaf" label="Leaf 证书 (PEM)" type="textarea" :rows="3" clearable />
          <CryptoPanel v-model="certChain.intermediates" label="中间证书 (PEM, 可选)" type="textarea" :rows="2" clearable />
          <CryptoPanel v-model="certChain.roots" label="根证书 (PEM, 可选)" type="textarea" :rows="2" clearable />
          <Button variant="primary" block class="text-sm" @click="verifyChain">
            <ShieldCheckIcon class="w-3.5 h-3.5" /> 验证链
          </Button>
          <div v-if="certChainResult.error" class="text-xs text-red-400">{{ certChainResult.error }}</div>
          <div v-if="certChainResult.data" class="text-xs text-emerald-400 whitespace-pre-line">{{ certChainResult.data }}</div>
        </Card>

        <Card title="PKCS#12 (.pfx) 导入" class="space-y-3">
          <div class="flex gap-2">
            <Button variant="tool" block class="text-xs" @click="uploadPfx">
              <FolderOpenIcon class="w-3.5 h-3.5" /> 选择 PFX 文件
            </Button>
          </div>
          <Input v-model="pfx.password" label="密码" type="password" class="ck-trim-space" placeholder="PFX 密码" />
          <CryptoPanel v-model="pfx.data" label="PFX 数据 (Base64/Hex)" type="textarea" :rows="3" clearable />
          <div>
            <label class="input-label">输入格式</label>
            <Dropdown
              v-model="pfx.format"
              :options="[
                { value: 'base64', label: 'Base64' },
                { value: 'hex', label: 'Hex' }
              ]"
            />
          </div>
          <Button variant="primary" block class="text-sm" @click="parsePfx">解析</Button>
          <div v-if="pfxResult.error" class="text-xs text-red-400">{{ pfxResult.error }}</div>
        </Card>
      </div>

      <div class="sym-side">
        <Card title="PKCS#1 (PEM)">
          <textarea readonly class="result-area result-area-sm text-xs font-mono w-full min-h-[60px] resize-none bg-transparent outline-none border-none"
                    :value="keyConvResult.pkcs1"></textarea>
        </Card>
        <Card title="PKCS#8 (PEM)">
          <textarea readonly class="result-area result-area-sm text-xs font-mono w-full min-h-[60px] resize-none bg-transparent outline-none border-none"
                    :value="keyConvResult.pkcs8"></textarea>
        </Card>
        <Card title="公钥 (PEM)">
          <textarea readonly class="result-area result-area-sm text-xs font-mono w-full min-h-[60px] resize-none bg-transparent outline-none border-none"
                    :value="keyConvResult.pub"></textarea>
        </Card>
        <Card title="DER (Hex/Base64)">
          <textarea readonly class="result-area result-area-sm text-xs font-mono w-full min-h-[50px] resize-none bg-transparent outline-none border-none"
                    :value="keyConvResult.derHex"></textarea>
          <textarea readonly class="result-area result-area-sm text-xs font-mono w-full min-h-[50px] resize-none bg-transparent outline-none border-none mt-2"
                    :value="keyConvResult.derBase64"></textarea>
        </Card>
        <Card title="PFX 导入结果">
          <textarea readonly class="result-area result-area-sm text-xs font-mono w-full min-h-[60px] resize-none bg-transparent outline-none border-none"
                    :value="pfxResult.key"></textarea>
          <textarea readonly class="result-area result-area-sm text-xs font-mono w-full min-h-[60px] resize-none bg-transparent outline-none border-none mt-2"
                    :value="pfxResult.cert"></textarea>
          <textarea readonly class="result-area result-area-sm text-xs font-mono w-full min-h-[60px] resize-none bg-transparent outline-none border-none mt-2"
                    :value="pfxResult.ca"></textarea>
          <div v-if="pfxResult.info" class="mt-1 text-xs text-orange-300">证书: {{ pfxResult.info }}</div>
        </Card>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useRoute, useRouter } from 'vue-router'
import { WrenchIcon, ZapIcon, RefreshCwIcon, FolderOpenIcon, KeyIcon, ShieldCheckIcon } from '@lucide/vue'
import Card from '../components/Card.vue'
import Input from '../components/Input.vue'
import Button from '../components/Button.vue'
import ResultArea from '../components/ResultArea.vue'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import Dropdown from '../components/Dropdown.vue'
import AlgorithmDrawer from '../components/AlgorithmDrawer.vue'
import ByteBadge from '../components/ByteBadge.vue'
import { HexToString, StringToHex, Base64Encode, Base64Decode, XORCompute, URLEncode, URLDecode, UnicodeEncode, UnicodeDecode, GenerateRandom, PaddingApply, PaddingRemove, BaseConvert, TimestampConvert, ParseASN1, ParseASN1File, Base32Encode, Base32Decode, Base58Encode, Base58Decode, Bech32Encode, Bech32Decode, ParseJWT, ConvertKey, VerifyCertChain, ParsePKCS12, ParsePKCS12File, SelectFile } from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const route = useRoute()
const router = useRouter()
const { isDark } = storeToRefs(store)
const { addToHistory, showToast } = store

const tabs = [
  { id: 'encode', label: '编解码' },
  { id: 'xor', label: 'XOR / 进制' },
  { id: 'random', label: '随机 / 填充' },
  { id: 'timestamp', label: '时间戳' },
  { id: 'asn1', label: 'ASN.1' },
  { id: 'base', label: 'BaseX' },
  { id: 'jwt', label: 'JWT/JWK' },
  { id: 'keycert', label: 'Key/Cert' },
]
const activeTab = ref('encode')
const showPrinciple = ref(false)

const principles = {
  'encode': {
    title: '编解码工具原理',
    content: '设计目标: 在不同数据格式之间进行转换，便于数据传输和存储。\n常见编码:\n• Hex: 将二进制数据转换为十六进制字符串，每字节用两个字符表示。\n• Base64: 将二进制数据转换为64个可打印字符，常用于邮件附件和数据嵌入。\n• URL编码: 将特殊字符转换为%XX格式，确保URL安全传输。\n• Unicode: 将字符转换为\\uXXXX格式，处理多语言文本。\n应用场景: 数据传输、API通信、文件处理、国际化文本处理。'
  },
  'xor': {
    title: 'XOR 与进制转换原理',
    content: 'XOR运算: 二进制异或运算，相同为0，不同为1。特性：A⊕B⊕B=A，可逆性强。\n进制转换: 在不同进制间转换数值表示。\n常见进制:\n• 二进制 (Base2): 计算机底层表示。\n• 十进制 (Base10): 人类日常使用。\n• 十六进制 (Base16): 紧凑表示二进制数据。\n应用场景: 密码学运算、数据校验、底层编程、网络协议。'
  },
  'random': {
    title: '随机数与填充原理',
    content: '随机数生成: 使用密码学安全的随机数生成器 (CSPRNG) 生成不可预测的随机数据。\n填充方式:\n• PKCS7: 最通用标准，填充值等于填充字节数。\n• Zero Padding: 填充0x00字节。\n• ISO10126: 随机填充，最后一个字节记录长度。\n安全要求: 密码学应用必须使用密码学安全的随机数源。\n应用场景: 密钥生成、IV/Nonce生成、数据对齐。'
  },
  'timestamp': {
    title: '时间戳转换原理',
    content: 'Unix时间戳: 自1970年1月1日00:00:00 UTC以来的秒数（或毫秒数）。\n精度选择:\n• 秒级 (10位): 传统Unix时间戳。\n• 毫秒级 (13位): JavaScript常用。\n格式转换: 在时间戳和人类可读日期格式之间转换。\n应用场景: 日志分析、API时间处理、数据库时间存储、跨时区协调。'
  },
  'asn1': {
    title: 'ASN.1 解析原理',
    content: 'ASN.1 (Abstract Syntax Notation One): 定义数据结构的标准表示法。\nDER编码: ASN.1的一种二进制编码规则，用于X.509证书、PKCS标准等。\nTLV结构: Tag-Length-Value，ASN.1的基本编码单元。\n常见应用:\n• X.509证书结构解析\n• RSA/EC私钥格式 (PKCS#1/PKCS#8)\n• CSR证书请求解析\n• CRL证书吊销列表\n应用场景: 证书管理、密钥格式转换、安全协议调试。'
  },
  'base': {
    title: 'BaseX 编码原理',
    content: '设计目标: 使用不同字符集对二进制数据进行编码。\n常见变体:\n• Base32: 使用A-Z和2-7，不区分大小写，适合人类输入。\n• Base58: 比特币使用，去除易混淆字符(0OIl)。\n• Base58Check: Base58 + 4字节校验和。\n• Bech32: 比特币SegWit地址格式，包含纠错能力。\n优势: 不同编码在可读性、URL安全性和纠错能力上各有侧重。\n应用场景: 区块链地址、DNS编码、人类可读标识符。'
  },
  'jwt': {
    title: 'JWT/JWK 原理',
    content: 'JWT (JSON Web Token): 用于身份认证的开放标准 (RFC 7519)。\n结构: Header.Payload.Signature，三部分用.分隔。\n签名算法:\n• HS256: HMAC-SHA256，对称密钥。\n• RS256: RSA-SHA256，非对称密钥。\n• ES256: ECDSA-SHA256，椭圆曲线。\nJWK (JSON Web Key): 密钥的JSON表示格式。\n安全注意: JWT签名验证必须严格，避免算法混淆攻击。\n应用场景: API认证、单点登录 (SSO)、身份令牌。'
  },
  'keycert': {
    title: '密钥与证书工具原理',
    content: '密钥转换: 在不同格式间转换密钥表示。\n常见格式:\n• PEM: Base64编码，带BEGIN/END标记。\n• DER: 二进制编码。\n• PKCS#12 (.p12/.pfx): 包含私钥和证书的加密容器。\n证书链验证: 从终端证书到根CA的信任链验证。\n应用场景: TLS配置、证书导入导出、密钥管理、PKI部署。'
  }
}
const currentPrinciple = computed(() => {
  return principles[activeTab.value] || { title: '', content: '' }
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

  if (sections.length === 0) {
    return [{ title: '详细说明', content: lines.filter(l => l.trim()) }]
  }
  return sections
})

function syncTabFromRoute() {
  const tab = typeof route.query.tab === 'string' ? route.query.tab : ''
  activeTab.value = tabs.some(item => item.id === tab) ? tab : 'encode'
}

function handleTabChange(tabId) {
  activeTab.value = tabId
  router.replace({ path: '/tools', query: tabId === 'encode' ? {} : { tab: tabId } })
}

watch(() => route.query.tab, syncTabFromRoute, { immediate: true })

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
