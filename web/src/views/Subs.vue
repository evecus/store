<template>
  <div class="page-card">
    <div class="toolbar">
      <el-button type="primary" @click="openCreate">
        <el-icon><Plus /></el-icon>新建订阅
      </el-button>
      <el-button @click="load">
        <el-icon><Refresh /></el-icon>刷新
      </el-button>
    </div>

    <el-table :data="subs" v-loading="loading" stripe>
      <el-table-column prop="name" label="名称" min-width="140" />
      <el-table-column label="类型" width="90">
        <template #default="{ row }">
          <el-tag size="small">{{ row.source || 'remote' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="url" label="URL" min-width="220" show-overflow-tooltip />
      <el-table-column label="操作" width="260" fixed="right">
        <template #default="{ row }">
          <el-button size="small" @click="openEdit(row)">编辑</el-button>
          <el-button size="small" @click="preview(row)">预览</el-button>
          <el-button size="small" type="danger" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="dialog" :title="editing ? '编辑订阅' : '新建订阅'" width="640px" destroy-on-close>
      <el-form label-width="90px">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="订阅名称" />
        </el-form-item>
        <el-form-item label="URL">
          <el-input v-model="form.url" placeholder="订阅链接（留空则使用下方内容）" />
        </el-form-item>
        <el-form-item label="User-Agent">
          <el-input v-model="form.ua" placeholder="自定义 UA（可选）" />
        </el-form-item>
        <el-form-item label="内容">
          <el-input v-model="form.content" type="textarea" :rows="5" placeholder="本地订阅内容（可选）" />
        </el-form-item>
        <el-form-item label="操作器">
          <el-input v-model="form.processText" type="textarea" :rows="4" placeholder="每行一个操作器，例如：Sort Operator 或 Type Filter" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="previewDialog" title="选择预览客户端" width="420px">
      <div class="target-grid">
        <el-button
          v-for="t in targets"
          :key="t"
          class="target-btn"
          @click="openPreview(t)"
        >{{ targetLabel(t) }}</el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { listSubs, createSub, patchSub, deleteSub, getTargets } from '../api'

const subs = ref([])
const loading = ref(false)
const saving = ref(false)
const dialog = ref(false)
const editing = ref(false)
const previewDialog = ref(false)
const previewName = ref('')
const form = ref({})

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

function defaultForm() {
  return { name: '', url: '', ua: '', content: '', processText: '' }
}

async function load() {
  loading.value = true
  try {
    const [{ data }, tg] = await Promise.all([listSubs(), getTargets().catch(() => null)])
    subs.value = data
    if (tg && Array.isArray(tg.data) && tg.data.length) targets.value = tg.data
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '加载失败')
  } finally {
    loading.value = false
  }
}

function parseProcess(text) {
  if (!text) return []
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const space = line.indexOf(' ')
      if (space === -1) return { type: line, args: {} }
      const type = line.slice(0, space)
      let args = {}
      try {
        args = JSON.parse(line.slice(space + 1))
      } catch {
        args = line.slice(space + 1)
      }
      return { type, args }
    })
}

function processToText(ops) {
  return (ops || [])
    .map((op) => (typeof op.args === 'object' && Object.keys(op.args || {}).length ? `${op.type} ${JSON.stringify(op.args)}` : op.type))
    .join('\n')
}

function openCreate() {
  editing.value = false
  form.value = defaultForm()
  dialog.value = true
}

function openEdit(row) {
  editing.value = true
  form.value = {
    name: row.name,
    url: row.url || '',
    ua: row.ua || '',
    content: row.content || '',
    processText: processToText(row.process),
  }
  dialog.value = true
}

async function save() {
  if (!form.value.name) {
    ElMessage.warning('请输入名称')
    return
  }
  saving.value = true
  try {
    const data = { ...form.value, process: parseProcess(form.value.processText) }
    delete data.processText
    if (editing.value) {
      await patchSub(form.value.name, data)
    } else {
      await createSub(data)
    }
    ElMessage.success('已保存')
    dialog.value = false
    await load()
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '保存失败')
  } finally {
    saving.value = false
  }
}

async function remove(row) {
  try {
    await ElMessageBox.confirm(`确认删除订阅「${row.name}」？`, '提示', { type: 'warning' })
    await deleteSub(row.name)
    ElMessage.success('已删除')
    await load()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e.response?.data?.message || '删除失败')
  }
}

function preview(row) {
  previewName.value = row.name
  previewDialog.value = true
}

function openPreview(target) {
  const token = localStorage.getItem('token') || ''
  const base = location.origin + location.pathname.replace(/\/[^/]*$/, '')
  const url = `${base}/download/${encodeURIComponent(previewName.value)}?target=${encodeURIComponent(target)}&token=${encodeURIComponent(token)}&preview=1`
  window.open(url, '_blank')
  previewDialog.value = false
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
.target-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 10px;
}
.target-btn {
  width: 100%;
  justify-content: center;
}
</style>
