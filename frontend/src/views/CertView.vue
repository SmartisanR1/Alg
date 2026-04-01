<template>
  <PageLayout title="证书管理" subtitle="CSR 生成 · 证书签发 · 自签名证书 · 国际/国密支持"
              icon-bg="bg-emerald-500/20"
              :tabs="tabs" :active-tab="activeTab" @tab-change="activeTab = $event">
    <template #icon>
      <ShieldCheckIcon class="w-4 h-4 text-emerald-400" />
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
            <p>{{ currentPrinciple.content }}</p>
          </div>
          <div class="mt-6 flex justify-end">
            <button @click="showPrinciple = false" class="ck-btn-primary px-6">确定</button>
          </div>
        </div>
      </div>
    </transition>

    <!-- Certificate Parsing -->
    <div v-show="activeTab === 'parse'" class="flex flex-col lg:flex-row gap-4 animate-fade-in h-full">
      <div class="w-full lg:w-[280px] space-y-3 shrink-0">
        <div class="ck-card space-y-3">
          <p class="ck-section-title">PEM 证书解析</p>
          <div class="flex gap-2 mb-2">
            <button @click="uploadCertFile" class="ck-btn-secondary flex-1 justify-center text-[11px] py-1.5">
              <UploadIcon class="w-3.5 h-3.5" /> 上传证书
            </button>
          </div>
          <CryptoPanel v-model="certInput" label="证书内容 (PEM)" type="textarea" :rows="10" placeholder="粘贴 -----BEGIN CERTIFICATE----- ..." />
          <button @click="parseCert" class="ck-btn-primary w-full justify-center py-2">解析证书</button>
        </div>
      </div>
      <div class="flex-1 min-w-0">
        <div class="ck-card h-full flex flex-col">
          <CryptoPanel v-model="certResult.data" label="解析详情 (X.509 结构化数据)" type="result" :success="certResult.success" copyable />
          <div v-if="certResult.error" class="mt-2 text-xs text-red-400">{{ certResult.error }}</div>
        </div>
      </div>
    </div>

    <!-- CSR Generation -->
    <div v-show="activeTab === 'csr'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card space-y-4">
          <p class="ck-section-title">CSR 请求信息</p>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="ck-label">通用名称 (CN)</label>
              <input v-model="csr.cn" class="ck-input" placeholder="example.com" />
            </div>
            <div>
              <label class="ck-label">组织 (O)</label>
              <input v-model="csr.o" class="ck-input" placeholder="Organization" />
            </div>
            <div>
              <label class="ck-label">国家 (C)</label>
              <input v-model="csr.c" class="ck-input" placeholder="CN" />
            </div>
            <div>
              <label class="ck-label">省份 (ST)</label>
              <input v-model="csr.st" class="ck-input" placeholder="Beijing" />
            </div>
          </div>
          <div>
            <label class="ck-label">算法 & 用途</label>
            <div class="grid grid-cols-2 gap-3">
              <select v-model="csr.algo" class="ck-select">
                <option value="RSA2048">RSA 2048</option>
                <option value="RSA4096">RSA 4096</option>
                <option value="ECC-P256">ECC P-256</option>
                <option value="SM2">国密 SM2</option>
              </select>
              <select v-model="csr.type" class="ck-select" :disabled="csr.algo !== 'SM2'">
                <option value="both">通用 (签名+加密)</option>
                <option value="sign">仅签名</option>
                <option value="encrypt">仅加密</option>
              </select>
            </div>
          </div>
          <button @click="genCSR" class="ck-btn-primary w-full justify-center py-2">生成 CSR</button>
        </div>
      </div>
      <div class="ck-stack">
        <div class="ck-card flex flex-col">
          <CryptoPanel v-model="csrResult.data" label="生成的 CSR (PEM)" type="result" :success="csrResult.success" copyable />
          <div v-if="csrResult.error" class="mt-2 text-xs text-red-400">{{ csrResult.error }}</div>
          <div v-if="csrResult.success" class="mt-4 flex gap-2">
            <button @click="downloadFile(csrResult.data, 'request.csr')" class="ck-btn-success flex-1 justify-center text-xs">
              <DownloadIcon class="w-3.5 h-3.5" /> 下载 CSR
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- CSR Signing -->
    <div v-show="activeTab === 'sign'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card space-y-4">
          <p class="ck-section-title">上传 CSR 签发</p>
          <CryptoPanel v-model="signReq.csr" label="CSR 内容 (PEM)" type="textarea" :rows="4" placeholder="粘贴 -----BEGIN CERTIFICATE REQUEST----- ..." />
          
          <div class="flex items-center gap-2 mb-2">
            <button @click="signShowAdvanced = !signShowAdvanced" class="text-[11px] text-violet-400 flex items-center gap-1 hover:text-violet-300 transition-colors">
              <SettingsIcon class="w-3 h-3" /> 高级选项 (SAN/扩展用途)
              <ChevronDownIcon class="w-3 h-3 transition-transform" :class="{'rotate-180': signShowAdvanced}" />
            </button>
          </div>

          <transition name="fade">
            <div v-if="signShowAdvanced" class="space-y-4 p-3 rounded-lg border transition-colors"
                 :class="isDark ? 'border-dark-border/50 bg-dark-bg/30' : 'border-gray-200 bg-gray-50'">
              <div class="grid grid-cols-2 gap-3">
                <div class="flex items-center gap-2">
                  <label class="ck-label !mb-0">基本约束:</label>
                  <div class="flex rounded-md overflow-hidden border h-7"
                       :class="isDark ? 'border-dark-border' : 'border-gray-200'">
                    <button @click="signReq.isCA = false" class="px-2 text-[10px] transition-colors" :class="!signReq.isCA ? 'bg-violet-500 text-white' : (isDark ? 'bg-dark-surface text-dark-muted' : 'bg-white text-gray-500')">用户</button>
                    <button @click="signReq.isCA = true" class="px-2 text-[10px] transition-colors" :class="signReq.isCA ? 'bg-violet-500 text-white' : (isDark ? 'bg-dark-surface text-dark-muted' : 'bg-white text-gray-500')">中级CA</button>
                  </div>
                </div>
                <div v-if="signReq.isCA">
                  <label class="ck-label">路径长度限制</label>
                  <input v-model.number="signReq.pathLen" type="number" class="ck-input !h-7 !py-0" placeholder="-1 (无限制)" />
                </div>
              </div>
              <div>
                <label class="ck-label">使用者备用名称 (SAN)</label>
                <textarea v-model="signReq.sanRaw" class="ck-input !h-16 text-[10px]" placeholder="每行一个 DNS:www.domain.com 或 IP:1.1.1.1"></textarea>
              </div>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="ck-label">CRL 分发点 (CDP)</label>
                  <textarea v-model="signReq.crlRaw" class="ck-input !h-16 text-[10px]" placeholder="http://crl.example.com/ca.crl"></textarea>
                </div>
                <div>
                  <label class="ck-label">OCSP 服务地址</label>
                  <textarea v-model="signReq.ocspRaw" class="ck-input !h-16 text-[10px]" placeholder="http://ocsp.example.com"></textarea>
                </div>
              </div>

              <div>
                <label class="ck-label">证书策略 (Policy OIDs)</label>
                <textarea v-model="signReq.policyRaw" class="ck-input !h-12 text-[10px]" placeholder="例如 2.5.29.32.0 (每行一个 OID)"></textarea>
              </div>

              <div>
                <label class="ck-label">增强密钥用途</label>
                <div class="grid grid-cols-2 gap-2">
                  <label v-for="eku in extKeyUsageOptions" :key="eku.value" class="flex items-center gap-2 text-[10px] hover:text-violet-400 cursor-pointer"
                         :class="isDark ? 'text-dark-muted' : 'text-gray-500'">
                    <input type="checkbox" v-model="signReq.extKeyUsage" :value="eku.value" class="rounded border-dark-border bg-dark-bg"> {{ eku.label }}
                  </label>
                </div>
              </div>
            </div>
          </transition>

          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="ck-label">有效期 (天)</label>
              <input v-model.number="signReq.days" type="number" class="ck-input" />
            </div>
            <div>
              <label class="ck-label">证书用途</label>
              <select v-model="signReq.type" class="ck-select">
                <option value="both">通用 (签名+加密)</option>
                <option value="sign">仅签名</option>
                <option value="encrypt">仅加密</option>
              </select>
            </div>
          </div>
          <div>
            <label class="ck-label">算法体系</label>
            <select v-model="signReq.algo" class="ck-select">
              <option value="RSA">国际 RSA</option>
              <option value="ECC">国际 ECC</option>
              <option value="SM2">国密 SM2</option>
            </select>
          </div>
          <button @click="signCSR" class="ck-btn-primary w-full justify-center py-2">签发证书</button>
        </div>
      </div>
      <div class="ck-stack">
        <div class="ck-card flex flex-col">
          <CryptoPanel v-model="signResult.data" label="生成的证书 (PEM)" type="result" :success="signResult.success" copyable />
          <div v-if="signResult.error" class="mt-2 text-xs text-red-400">{{ signResult.error }}</div>
          <div v-if="signResult.success" class="mt-4 flex gap-2">
            <button @click="downloadFile(signResult.data, 'certificate.cer')" class="ck-btn-success flex-1 justify-center text-xs">
              <DownloadIcon class="w-3.5 h-3.5" /> 下载证书
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Direct Issuance (Internal CA) -->
    <div v-show="activeTab === 'self'" class="ck-workbench animate-fade-in">
      <div class="ck-stack">
        <div class="ck-card space-y-4">
          <div class="flex justify-between items-center">
            <p class="ck-section-title">直接签发 (由内置 CA 签名)</p>
            <div class="flex gap-2">
              <button @click="downloadRootCert('SM2')" class="text-[10px] px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-all flex items-center gap-1">
                <DownloadIcon class="w-3 h-3" /> SM2 根证书
              </button>
              <button @click="downloadRootCert('RSA')" class="text-[10px] px-2 py-1 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 hover:bg-blue-500/20 transition-all flex items-center gap-1">
                <DownloadIcon class="w-3 h-3" /> RSA 根证书
              </button>
            </div>
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="ck-label">通用名称 (CN)</label>
              <input v-model="selfReq.cn" class="ck-input" placeholder="www.example.com" />
            </div>
            <div>
              <label class="ck-label">组织 (O)</label>
              <input v-model="selfReq.o" class="ck-input" placeholder="CryptoKit User" />
            </div>
            <div>
              <label class="ck-label">有效期 (天)</label>
              <input v-model.number="selfReq.days" type="number" class="ck-input" />
            </div>
            <div>
              <label class="ck-label">签名算法</label>
              <select v-model="selfReq.algo" class="ck-select">
                <option value="RSA">RSA (2048)</option>
                <option value="ECC">ECC (P-256)</option>
                <option value="SM2">国密 SM2</option>
              </select>
            </div>
          </div>

          <div class="flex items-center gap-2">
            <button @click="selfShowAdvanced = !selfShowAdvanced" class="text-[11px] text-violet-400 flex items-center gap-1 hover:text-violet-300 transition-colors">
              <SettingsIcon class="w-3 h-3" /> 扩展高级选项 (符合 gmcert.org 标准)
              <ChevronDownIcon class="w-3 h-3 transition-transform" :class="{'rotate-180': selfShowAdvanced}" />
            </button>
          </div>

          <transition name="fade">
            <div v-if="selfShowAdvanced" class="space-y-4 p-3 rounded-lg border transition-colors"
                 :class="isDark ? 'border-dark-border/50 bg-dark-bg/30' : 'border-gray-200 bg-gray-50'">
              
              <div class="grid grid-cols-2 gap-4">
                <div class="flex items-center gap-2">
                  <label class="ck-label !mb-0">基本约束:</label>
                  <div class="flex rounded-md overflow-hidden border h-7"
                       :class="isDark ? 'border-dark-border' : 'border-gray-200'">
                    <button @click="selfReq.isCA = false" class="px-2 text-[10px] transition-colors" :class="!selfReq.isCA ? 'bg-violet-500 text-white' : (isDark ? 'bg-dark-surface text-dark-muted' : 'bg-white text-gray-500')">用户</button>
                    <button @click="selfReq.isCA = true" class="px-2 text-[10px] transition-colors" :class="selfReq.isCA ? 'bg-violet-500 text-white' : (isDark ? 'bg-dark-surface text-dark-muted' : 'bg-white text-gray-500')">中级CA</button>
                  </div>
                </div>
                <div v-if="selfReq.isCA">
                  <label class="ck-label">路径长度限制</label>
                  <input v-model.number="selfReq.pathLen" type="number" class="ck-input !h-7 !py-0" placeholder="-1 (无限制)" />
                </div>
              </div>

              <div>
                <label class="ck-label">使用者备用名称 (SAN)</label>
                <textarea v-model="selfReq.sanRaw" class="ck-input !h-16 text-[10px]" placeholder="DNS:example.com&#10;IP:127.0.0.1"></textarea>
              </div>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="ck-label">CRL 分发点 (CDP)</label>
                  <textarea v-model="selfReq.crlRaw" class="ck-input !h-16 text-[10px]" placeholder="http://crl.example.com/ca.crl"></textarea>
                </div>
                <div>
                  <label class="ck-label">OCSP 服务地址</label>
                  <textarea v-model="selfReq.ocspRaw" class="ck-input !h-16 text-[10px]" placeholder="http://ocsp.example.com"></textarea>
                </div>
              </div>

              <div>
                <label class="ck-label">证书策略 (Policy OIDs)</label>
                <textarea v-model="selfReq.policyRaw" class="ck-input !h-12 text-[10px]" placeholder="例如 2.5.29.32.0 (每行一个 OID)"></textarea>
              </div>

              <div>
                <label class="ck-label">密钥用途 (Key Usage)</label>
                <div class="grid grid-cols-2 gap-x-2 gap-y-1">
                  <label v-for="ku in keyUsageOptions" :key="ku.value" class="flex items-center gap-2 text-[10px] hover:text-violet-400 cursor-pointer"
                         :class="isDark ? 'text-dark-muted' : 'text-gray-500'">
                    <input type="checkbox" v-model="selfReq.keyUsage" :value="ku.value" class="rounded border-dark-border bg-dark-bg"> {{ ku.label }}
                  </label>
                </div>
              </div>

              <div>
                <label class="ck-label">增强用途 (Ext Key Usage)</label>
                <div class="grid grid-cols-2 gap-x-2 gap-y-1">
                  <label v-for="eku in extKeyUsageOptions" :key="eku.value" class="flex items-center gap-2 text-[10px] hover:text-violet-400 cursor-pointer"
                         :class="isDark ? 'text-dark-muted' : 'text-gray-500'">
                    <input type="checkbox" v-model="selfReq.extKeyUsage" :value="eku.value" class="rounded border-dark-border bg-dark-bg"> {{ eku.label }}
                  </label>
                </div>
              </div>
            </div>
          </transition>

          <button @click="genSelfSigned" class="ck-btn-primary w-full justify-center mt-2">立即签发并生成结果</button>
        </div>
      </div>
      <div class="ck-stack">
        <!-- Certificate Result -->
        <div class="ck-card">
          <div class="flex justify-between items-center mb-1">
            <label class="ck-label !mb-0 text-emerald-400">生成的证书 (PEM)</label>
            <div class="flex gap-1">
              <button v-if="selfResult.cert" @click="copyText(selfResult.cert)" class="ck-copy-btn">
                <CopyIcon class="w-3 h-3" /> 复制
              </button>
            </div>
          </div>
          <div class="ck-result !min-h-[64px] !p-2 !text-[10px] break-all overflow-y-auto font-mono"
               :class="{'text-emerald-400/90': selfResult.success}">
            {{ selfResult.cert || '等待生成...' }}
          </div>
        </div>

        <!-- CSR Result -->
        <div class="ck-card">
          <div class="flex justify-between items-center mb-1">
            <label class="ck-label !mb-0 text-violet-400">生成的 CSR (PEM)</label>
            <div class="flex gap-1">
              <button v-if="selfResult.csr" @click="copyText(selfResult.csr)" class="ck-copy-btn">
                <CopyIcon class="w-3 h-3" /> 复制
              </button>
            </div>
          </div>
          <div class="ck-result !min-h-[64px] !p-2 !text-[10px] break-all overflow-y-auto font-mono text-violet-400/90">
            {{ selfResult.csr || '等待生成...' }}
          </div>
        </div>

        <!-- Private Key Result -->
        <div class="ck-card">
          <div class="flex justify-between items-center mb-1">
            <label class="ck-label !mb-0 text-amber-400">配套私钥 (PEM)</label>
            <div class="flex gap-1">
              <button v-if="selfResult.key" @click="copyText(selfResult.key)" class="ck-copy-btn">
                <CopyIcon class="w-3 h-3" /> 复制
              </button>
            </div>
          </div>
          <div class="ck-result !min-h-[64px] !p-2 !text-[10px] break-all overflow-y-auto font-mono text-amber-400/90">
            {{ selfResult.key || '等待生成...' }}
          </div>
        </div>

        <!-- Download Buttons -->
        <div v-if="selfResult.success" class="grid grid-cols-3 gap-2 pb-4 shrink-0">
          <button @click="downloadFile(selfResult.cert, 'certificate.cer')" class="ck-btn-success justify-center text-[10px] px-1">
            <DownloadIcon class="w-3 h-3" /> 证书下载
          </button>
          <button @click="downloadFile(selfResult.csr, 'request.csr')" class="ck-btn-primary justify-center text-[10px] px-1">
            <FileIcon class="w-3 h-3" /> CSR下载
          </button>
          <button @click="downloadFile(selfResult.key, 'private.key')" class="ck-btn-secondary justify-center text-[10px] px-1">
            <KeyIcon class="w-3 h-3" /> 私钥下载
          </button>
        </div>
      </div>
    </div>

    <!-- Dual Certificate (GM/T 0010) -->
    <div v-show="activeTab === 'dual'" class="ck-workbench animate-fade-in">
      <div class="ck-stack overflow-y-auto pr-1 custom-scrollbar">
        <div class="ck-card space-y-4">
          <div class="flex justify-between items-center">
            <p class="ck-section-title">国密双证书签发 (签名+加密)</p>
            <button @click="downloadRootCert('SM2')" class="text-[10px] px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-all flex items-center gap-1">
              <DownloadIcon class="w-3 h-3" /> SM2 根证书
            </button>
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="ck-label">通用名称 (CN)</label>
              <input v-model="dualReq.cn" class="ck-input" placeholder="www.example.com" />
            </div>
            <div>
              <label class="ck-label">组织 (O)</label>
              <input v-model="dualReq.o" class="ck-input" placeholder="CryptoKit User" />
            </div>
            <div>
              <label class="ck-label">有效期 (天)</label>
              <input v-model.number="dualReq.days" type="number" class="ck-input" />
            </div>
            <div>
              <label class="ck-label">签名算法</label>
              <select v-model="dualReq.algo" class="ck-select" disabled>
                <option value="SM2">国密 SM2 (标准要求)</option>
              </select>
            </div>
          </div>

          <div class="flex items-center gap-2">
            <button @click="dualShowAdvanced = !dualShowAdvanced" class="text-[11px] text-violet-400 flex items-center gap-1 hover:text-violet-300 transition-colors">
              <SettingsIcon class="w-3 h-3" /> 高级选项 (符合 gmcert.org 标准)
              <ChevronDownIcon class="w-3 h-3 transition-transform" :class="{'rotate-180': dualShowAdvanced}" />
            </button>
          </div>

          <transition name="fade">
            <div v-if="dualShowAdvanced" class="space-y-4 p-3 rounded-lg border transition-colors"
                 :class="isDark ? 'border-dark-border/50 bg-dark-bg/30' : 'border-gray-200 bg-gray-50'">
              
              <div>
                <label class="ck-label">使用者备用名称 (SAN)</label>
                <textarea v-model="dualReq.sanRaw" class="ck-input !h-16 text-[10px]" placeholder="DNS:example.com&#10;IP:127.0.0.1"></textarea>
              </div>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="ck-label">CRL 分发点 (CDP)</label>
                  <textarea v-model="dualReq.crlRaw" class="ck-input !h-16 text-[10px]" placeholder="http://crl.example.com/ca.crl"></textarea>
                </div>
                <div>
                  <label class="ck-label">OCSP 服务地址</label>
                  <textarea v-model="dualReq.ocspRaw" class="ck-input !h-16 text-[10px]" placeholder="http://ocsp.example.com"></textarea>
                </div>
              </div>

              <div>
                <label class="ck-label">证书策略 (Policy OIDs)</label>
                <textarea v-model="dualReq.policyRaw" class="ck-input !h-12 text-[10px]" placeholder="例如 2.5.29.32.0 (每行一个 OID)"></textarea>
              </div>
            </div>
          </transition>

          <button @click="genDualCerts" class="ck-btn-primary w-full justify-center mt-2 shadow-lg shadow-violet-500/10">立即签发双证书及信封</button>
        </div>
        
        <!-- Inline Principle for Dual Cert -->
        <div class="ck-card bg-gradient-to-br from-violet-500/5 to-transparent border-violet-500/10 shrink-0">
          <p class="ck-section-title text-violet-400">双证书体系说明 (GM/T 0010)</p>
          <div class="text-[11px] space-y-2 leading-relaxed opacity-80" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">
            <p>• <b>签名证书:</b> 用于身份认证，私钥由用户生成并严密保管。</p>
            <p>• <b>加密证书:</b> 用于加密通信，密钥对由 CA 生成并托管，通过数字信封下发。</p>
            <p>• <b>合规性:</b> 符合国密 GM/T 0010 及国标 GB/T 35275 标准。</p>
          </div>
        </div>
      </div>

      <div class="ck-stack h-full flex flex-col">
        <div v-if="dualResult.success" class="flex-1 min-h-0 flex flex-col space-y-3 animate-fade-in">
          <div class="grid grid-cols-2 gap-3 shrink-0">
            <div class="ck-card flex flex-col p-2.5">
              <div class="flex justify-between items-center mb-1.5">
                <span class="text-[10px] font-bold text-emerald-400">签名证书</span>
                <button @click="downloadFile(dualResult.signCert, 'sign.cer')" class="text-[9px] text-emerald-400 underline">下载</button>
              </div>
              <textarea readonly class="ck-result !min-h-[100px] !text-[9px] font-mono resize-none bg-transparent border-none outline-none overflow-y-auto" v-model="dualResult.signCert"></textarea>
            </div>
            <div class="ck-card flex flex-col p-2.5">
              <div class="flex justify-between items-center mb-1.5">
                <span class="text-[10px] font-bold text-cyan-400">加密证书</span>
                <button @click="downloadFile(dualResult.encryptCert, 'encrypt.cer')" class="text-[9px] text-cyan-400 underline">下载</button>
              </div>
              <textarea readonly class="ck-result !min-h-[100px] !text-[9px] font-mono resize-none bg-transparent border-none outline-none overflow-y-auto" v-model="dualResult.encryptCert"></textarea>
            </div>
          </div>
          
          <div class="ck-card flex-1 min-h-0 flex flex-col p-3">
            <div class="flex justify-between items-center mb-2 shrink-0">
              <span class="text-[11px] font-bold text-amber-400 flex items-center gap-1.5">
                <ShieldCheckIcon class="w-3.5 h-3.5" /> 加密私钥信封
              </span>
              <button @click="downloadFile(dualResult.enwrappedKey, 'enc_key.env')" class="ck-copy-btn !bg-amber-500/10 !text-amber-400">下载 .env</button>
            </div>
            <textarea readonly class="ck-result flex-1 !text-[10px] font-mono resize-none bg-transparent border-none outline-none overflow-y-auto" v-model="dualResult.enwrappedKey"></textarea>
          </div>
          
          <div class="ck-card shrink-0 flex flex-col p-3">
            <div class="flex justify-between items-center mb-2 shrink-0">
              <span class="text-[11px] font-bold text-violet-400 flex items-center gap-1.5">
                <KeyIcon class="w-3.5 h-3.5" /> 签名私钥 (PEM)
              </span>
              <button @click="downloadFile(dualResult.signKey, 'sign.key')" class="ck-copy-btn !bg-violet-500/10 !text-violet-400">下载 .key</button>
            </div>
            <textarea readonly class="ck-result !min-h-[60px] !max-h-[100px] !text-[10px] font-mono resize-none bg-transparent border-none outline-none overflow-y-auto" v-model="dualResult.signKey"></textarea>
          </div>
        </div>
        <div v-else class="ck-card h-full flex flex-col items-center justify-center text-dark-muted space-y-4 border-dashed opacity-60">
          <div class="w-16 h-16 rounded-full bg-dark-bg flex items-center justify-center">
            <ShieldCheckIcon class="w-8 h-8" />
          </div>
          <p class="text-xs">点击生成符合 GM/T 0010 标准的双证书</p>
        </div>
      </div>
    </div>
  </PageLayout>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ShieldCheckIcon, DownloadIcon, KeyIcon, SettingsIcon, ChevronDownIcon, FileIcon, CopyIcon, UploadIcon, InfoIcon, XIcon, PackageIcon, LockIcon } from 'lucide-vue-next'
import PageLayout from '../components/PageLayout.vue'
import CryptoPanel from '../components/CryptoPanel.vue'
import { 
  GenerateCSR, ParseCertificate, GenerateCertificate, GenerateSelfSignedCert, 
  GenerateInternalSignedCert, GenerateDualCertificates, GetInternalRootCert, SaveFile, SelectFile, ReadFile 
} from '../../wailsjs/go/main/App'
import { useAppStore } from '../stores/app'
import { storeToRefs } from 'pinia'

const store = useAppStore()
const { isDark } = storeToRefs(store)

const tabs = [
  { id: 'self', label: '直接签发' },
  { id: 'dual', label: '双证书签发 (GM)' },
  { id: 'parse', label: '证书解析' },
  { id: 'csr', label: 'CSR 生成' },
  { id: 'sign', label: '证书签发' },
]
const activeTab = ref('self')

// Principles modal / info
const showPrinciple = ref(false)
const principles = {
  parse: {
    title: '证书解析原理',
    content: '解析 PEM 格式的 X.509 证书。支持国际标准 (RSA/ECC) 和中国国密标准 (SM2)。通过解析 ASN.1 编码的 DER 数据，提取使用者(Subject)、发行者(Issuer)、有效期、公钥信息以及扩展项(Extensions)中的 OID 详细信息。'
  },
  csr: {
    title: 'CSR 生成原理',
    content: 'CSR (Certificate Signing Request) 是证书签名请求。它包含公钥和身份信息。生成过程中会先创建一对密钥，然后使用私钥对包含身份信息的请求进行签名。支持 RSA (2048/4096)、ECC (P-256) 和国密 SM2。'
  },
  sign: {
    title: 'CSR 签发原理',
    content: '使用 CA (证书颁发机构) 的私钥对用户提交的 CSR 进行签名。签发过程会将 CSR 中的公钥和身份信息包装进证书，并添加有效期、基本约束(CA标志)、使用者备用名称(SAN)等扩展项。'
  },
  self: {
    title: '直接签发原理',
    content: '此功能模拟 CA 签发流程。系统内置了国密 (SM2) 和国际 (RSA) 根证书。当您点击签发时，系统会为您生成私钥和 CSR，并使用内置的 Root CA 私钥对其进行签名，生成最终证书。您可以下载对应的根证书以进行验证。支持 OID 级别的扩展项配置，如 SAN、CDP、OCSP 和策略 OID。'
  },
  dual: {
    title: '双证书签发原理 (GM/T 0010)',
    content: '符合国密标准的双证书体系：\n1. 签名证书：用于身份认证和数字签名，私钥由用户生成并保管，CA 仅对公钥签名。\n2. 加密证书：用于数据加密和密钥交换，密钥对由 CA 生成，私钥通过数字信封 (GM/T 0010) 安全传输给用户。\n数字信封使用用户的签名公钥进行保护，确保只有持有签名私钥的用户才能解开信封获取加密私钥。'
  }
}

const currentPrinciple = computed(() => principles[activeTab.value])

const keyUsageOptions = [
  { label: '数字签名', value: 'digitalSignature' },
  { label: '不可否认', value: 'nonRepudiation' },
  { label: '密钥加密', value: 'keyEncipherment' },
  { label: '数据加密', value: 'dataEncipherment' },
  { label: '证书签名', value: 'keyCertSign' },
  { label: 'CRL签名', value: 'crlSign' },
]

const extKeyUsageOptions = [
  { label: '服务端认证', value: 'serverAuth' },
  { label: '客户端认证', value: 'clientAuth' },
  { label: '代码签名', value: 'codeSigning' },
  { label: '电子邮件保护', value: 'emailProtection' },
  { label: '时间戳', value: 'timeStamping' },
  { label: 'OCSP签名', value: 'ocspSigning' },
]

// Backend-driven download
async function downloadFile(content, filename) {
  if (!content) return
  await SaveFile(content, filename)
}

async function downloadRootCert(algo) {
  const root = await GetInternalRootCert(algo)
  if (root) {
    await SaveFile(root, `CryptoKit_${algo}_RootCA.cer`)
  }
}

// Parsing
const certInput = ref('')
const certResult = reactive({ data: '', error: '', success: null })

async function uploadCertFile() {
  const path = await SelectFile()
  if (path) {
    const content = await ReadFile(path)
    if (content) {
      certInput.value = content
      parseCert()
    }
  }
}

async function parseCert() {
  const r = await ParseCertificate(certInput.value)
  certResult.data = r.data; certResult.error = r.error; certResult.success = r.success
}

// CSR
const csr = reactive({ cn: 'CryptoKit Test', o: 'OpenSource', c: 'CN', l: 'Beijing', st: 'Beijing', ou: 'IT', algo: 'RSA2048', type: 'both' })
const csrResult = reactive({ data: '', error: '', success: null })

async function genCSR() {
  const r = await GenerateCSR(csr)
  csrResult.data = r.data; csrResult.error = r.error; csrResult.success = r.success
  if (r.success) {
    signReq.csr = r.data
  }
}

// CSR Signing
const signShowAdvanced = ref(false)
const signReq = reactive({ 
  csr: '', days: 365, type: 'both', algo: 'RSA', 
  isCA: false, sanRaw: '', extKeyUsage: [],
  crlRaw: '', ocspRaw: '', pathLen: -1, policyRaw: ''
})
const signResult = reactive({ data: '', error: '', success: null })

async function signCSR() {
  if (!signReq.csr) {
    signResult.error = '请先粘贴 CSR 内容'
    signResult.success = false
    return
  }
  const sanList = signReq.sanRaw.split('\n').map(s => s.trim()).filter(s => s)
  const crlList = signReq.crlRaw.split('\n').map(s => s.trim()).filter(s => s)
  const ocspList = signReq.ocspRaw.split('\n').map(s => s.trim()).filter(s => s)
  const policyList = signReq.policyRaw.split('\n').map(s => s.trim()).filter(s => s)
  
  const r = await GenerateCertificate({
    ...signReq,
    san: sanList,
    crlPoints: crlList,
    ocspUrls: ocspList,
    policies: policyList
  })
  signResult.data = r.data; signResult.error = r.error; signResult.success = r.success
}

// Direct Issuance (Internal CA)
const selfShowAdvanced = ref(false)
const selfReq = reactive({ 
  cn: 'www.cryptokit.com', o: 'CryptoKit User', c: 'CN', l: 'Beijing', st: 'Beijing', ou: 'Security',
  days: 365, algo: 'SM2', 
  keyUsage: ['digitalSignature', 'keyEncipherment'],
  extKeyUsage: ['serverAuth', 'clientAuth'],
  isCA: false,
  pathLen: -1,
  sanRaw: '',
  crlRaw: '',
  ocspRaw: '',
  policyRaw: ''
})
const selfResult = reactive({ cert: '', key: '', csr: '', success: null })

async function genSelfSigned() {
  const sanList = selfReq.sanRaw.split('\n').map(s => s.trim()).filter(s => s)
  const crlList = selfReq.crlRaw.split('\n').map(s => s.trim()).filter(s => s)
  const ocspList = selfReq.ocspRaw.split('\n').map(s => s.trim()).filter(s => s)
  const policyList = selfReq.policyRaw.split('\n').map(s => s.trim()).filter(s => s)

  const r = await GenerateInternalSignedCert({
    ...selfReq,
    san: sanList,
    crlPoints: crlList,
    ocspUrls: ocspList,
    policies: policyList
  })
  
  if (r.success) {
    selfResult.cert = r.cert
    selfResult.key = r.key
    selfResult.csr = r.csr
    selfResult.success = true
  } else {
    selfResult.success = false
    alert(r.error)
  }
}

// Dual Certificate (Internal CA)
const dualShowAdvanced = ref(false)
const dualReq = reactive({ 
  cn: 'DualCert User', o: 'CryptoKit User', c: 'CN', l: 'Beijing', st: 'Beijing', ou: 'Security',
  days: 365, algo: 'SM2', 
  keyUsage: ['digitalSignature', 'keyEncipherment'],
  extKeyUsage: ['serverAuth', 'clientAuth'],
  isCA: false,
  pathLen: -1,
  sanRaw: '',
  crlRaw: '',
  ocspRaw: '',
  policyRaw: ''
})
const dualResult = reactive({ signCert: '', signKey: '', encryptCert: '', enwrappedKey: '', success: null })

async function genDualCerts() {
  const sanList = dualReq.sanRaw.split('\n').map(s => s.trim()).filter(s => s)
  const crlList = dualReq.crlRaw.split('\n').map(s => s.trim()).filter(s => s)
  const ocspList = dualReq.ocspRaw.split('\n').map(s => s.trim()).filter(s => s)
  const policyList = dualReq.policyRaw.split('\n').map(s => s.trim()).filter(s => s)

  const r = await GenerateDualCertificates({
    ...dualReq,
    san: sanList,
    crlPoints: crlList,
    ocspUrls: ocspList,
    policies: policyList
  })
  
  if (r.success) {
    dualResult.signCert = r.signCert
    dualResult.signKey = r.signKey
    dualResult.encryptCert = r.encryptCert
    dualResult.enwrappedKey = r.enwrappedKey
    dualResult.success = true
  } else {
    dualResult.success = false
    alert(r.error)
  }
}

async function copyText(t) {
  if (!t) return
  await navigator.clipboard.writeText(t)
  store.showToast('已复制')
}
</script>
