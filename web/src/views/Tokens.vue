<template>
  <div class="page-card">
    <div class="toolbar">
      <el-button type="primary" @click="openCreate">
        <el-icon><Plus /></el-icon>生成分享令牌
      </el-button>
      <el-button @click="load">
        <el-icon><Refresh /></el-icon>刷新
      </el-button>
    </div>

    <el-table :data="tokens" v-loading="loading" stripe>
      <el-table-column prop="type" label="类型" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="row.type === 'sub' ? 'success' : 'warning'">{{ row.type }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="name" label="目标名称" min-width="140" />
      <el-table-column prop="token" label="Token" min-width="200" show-overflow-tooltip />
      <el-table-column label="客户端/格式" width="170">
        <template #default="{ row }">
          <el-select v-model="row.target" size="small" style="width:100%">
            <el-option v-for="t in targets" :key="t" :label="targetLabel(t)" :value="t" />
          </el-select>
        </template>
      </el-table-column>
      <el-table-column label="模式" width="110">
        <template #default="{ row }">
          <el-tag size="small">{{ row.mode || 'duration' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="已用/限制" width="110">
        <template #default="{ row }">
          <span>{{ row.usedCount ?? 0 }} / {{ row.count || '-' }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="300" fixed="right">
        <template #default="{ row }">
          <el-button size="small" @click="copyUrl(row)">复制链接</el-button>
          <el-button size="small" @click="preview(row)">预览</el-button>
          <el-button size="small" @click="openRaw(row)">下载</el-button>
          <el-button size="small" type="danger" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="dialog" title="生成分享令牌" width="560px" destroy-on-close>
      <el-form label-width="90px">
        <el-form-item label="类型">
          <el-radio-group v-model="form.type">
            <el-radio-button label="sub">订阅</el-radio-button>
            <el-radio-button label="col">组合订阅</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="目标">
          <el-select v-model="form.name" filterable style="width:100%">
            <el-option v-for="s in (form.type === 'sub' ? subs : cols)" :key="s.name" :label="s.name" :value="s.name" />
          </el-select>
        </el-form-item>
        <el-form-item label="客户端">
          <el-select v-model="form.target" filterable style="width:100%">
            <el-option v-for="t in targets" :key="t" :label="targetLabel(t)" :value="t" />
          </el-select>
        </el-form-item>
        <el-form-item label="模式">
          <el-radio-group v-model="form.mode">
            <el-radio-button label="duration">时长</el-radio-button>
            <el-radio-button label="count">次数</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="form.mode === 'duration'" label="有效期">
          <el-select v-model="form.seconds">
            <el-option :value="3600" label="1 小时" />
            <el-option :value="86400" label="1 天" />
            <el-option :value="604800" label="7 天" />
            <el-option :value="2592000" label="30 天" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.mode === 'count'" label="次数">
          <el-input-number v-model="form.count" :min="1" />
        </el-form-item>
      </el-form>
      <el-alert type="info" :closable="false" style="margin-top:4px">
        分享链接末尾的 <code>target=</code> 参数决定输出的客户端格式；客户端订阅时填这个链接即可。若需换客户端，手动把 <code>target</code> 改成下表格式即可。
      </el-alert>
      <template #footer>
        <el-button @click="dialog = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">生成</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { listTokens, createToken, deleteToken, listSubs, listCollections, getTargets } from '../api'

const tokens = ref([])
const subs = ref([])
const cols = ref([])
const loading = ref(false)
const saving = ref(false)
const dialog = ref(false)
const form = ref({ type: 'sub', name: '', target: 'mihomo', mode: 'duration', seconds: 604800, count: 10 })

const targetLabels = {
  mihomo: 'Clash / Mihomo',
  clash: 'Clash',
  stash: 'Stash',
  surge: 'Surge',
  'surge-mac': 'Surge Mac',
  surfboard: 'Surfboard',
  loon: 'Loon',
  shadowrocket: 'Shadowrocket',
  qx: 'Quantumult X',
  'sing-box': 'sing-box',
  v2ray: 'V2Ray',
  egern: 'Egern',
  json: 'JSON',
  uri: '通用链接 (URI)',
}
const targets = ref(Object.keys(targetLabels))

function targetLabel(t) {
  return targetLabels[t] || t
}

function shareUrl(row, extra = '') {
  const kind = row.type === 'sub' ? 'sub' : 'col'
  const base = location.origin + location.pathname.replace(/\/[^/]*$/, '')
  return `${base}/share/${kind}/${encodeURIComponent(row.name)}?token=${row.token}&target=${encodeURIComponent(row.target || 'mihomo')}${extra}`
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text)
    return
  }
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.position = 'fixed'
  ta.style.opacity = '0'
  document.body.appendChild(ta)
  ta.focus()
  ta.select()
  const ok = document.execCommand('copy')
  document.body.removeChild(ta)
  if (!ok) throw new Error('copy failed')
}

async function copyUrl(row) {
  const url = shareUrl(row)
  try {
    await copyText(url)
    ElMessage.success('分享链接已复制')
  } catch {
    ElMessage.warning('复制失败，请手动复制：' + url)
  }
}

function preview(row) {
  window.open(shareUrl(row, '&preview=1'), '_blank')
}

function openRaw(row) {
  window.open(shareUrl(row), '_blank')
}

async function load() {
  loading.value = true
  try {
    const [t, s, c, tg] = await Promise.all([listTokens(), listSubs(), listCollections(), getTargets()])
    tokens.value = t.data
    subs.value = s.data
    cols.value = c.data
    if (Array.isArray(tg.data) && tg.data.length) targets.value = tg.data
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '加载失败')
  } finally {
    loading.value = false
  }
}

function openCreate() {
  form.value = { type: 'sub', name: subs.value[0]?.name || '', target: 'mihomo', mode: 'duration', seconds: 604800, count: 10 }
  dialog.value = true
}

async function save() {
  if (!form.value.name) {
    ElMessage.warning('请选择目标订阅')
    return
  }
  saving.value = true
  try {
    const { data } = await createToken({
      type: form.value.type,
      name: form.value.name,
      target: form.value.target,
      mode: form.value.mode,
      seconds: form.value.seconds,
      count: form.value.count,
    })
    ElMessage.success('令牌已生成')
    dialog.value = false
    await load()
    copyUrl(data)
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '生成失败')
  } finally {
    saving.value = false
  }
}

async function remove(row) {
  try {
    await ElMessageBox.confirm(`确认删除令牌 ${row.token}？`, '提示', { type: 'warning' })
    await deleteToken(row.token)
    ElMessage.success('已删除')
    await load()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e.response?.data?.message || '删除失败')
  }
}

onMounted(load)
</script>

<style scoped>
.page-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
  padding: 20px;
}
.toolbar { margin-bottom: 16px; display: flex; gap: 10px; }
</style>
