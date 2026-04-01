import { createRouter, createWebHashHistory } from 'vue-router'

const routes = [
  { path: '/', redirect: '/symmetric' },
  { path: '/symmetric', component: () => import('../views/SymmetricView.vue'), meta: { title: '对称加密' } },
  { path: '/asymmetric', component: () => import('../views/AsymmetricView.vue'), meta: { title: '非对称加密' } },
  { path: '/hash', component: () => import('../views/HashView.vue'), meta: { title: '哈希 / HMAC' } },
  { path: '/mac', component: () => import('../views/MacView.vue'), meta: { title: 'MAC / KDF' } },
  { path: '/finance', component: () => import('../views/FinanceView.vue'), meta: { title: '金融数据密码' } },
  { path: '/pqc', component: () => import('../views/PQCView.vue'), meta: { title: '后量子密码' } },
  { path: '/gmpqc', component: () => import('../views/GMPQCView.vue'), meta: { title: '国密后量子密码' } },
  { path: '/tools', component: () => import('../views/ToolsView.vue'), meta: { title: '工具箱' } },
  { path: '/packet', component: () => import('../views/PacketView.vue'), meta: { title: '报文收发' } },
  { path: '/bigint', component: () => import('../views/BigIntView.vue'), meta: { title: '大数运算' } },
  { path: '/cert', component: () => import('../views/CertView.vue'), meta: { title: '证书管理' } },
  { path: '/file', component: () => import('../views/FileView.vue'), meta: { title: '文件加解密' } },
]

export default createRouter({
  history: createWebHashHistory(),
  routes,
})
