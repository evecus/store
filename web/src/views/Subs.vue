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
        <el-form-item label="类型">
          <el-radio-group v-model="form.sourceType">
            <el-radio-button label="remote">远程</el-radio-button>
            <el-radio-button label="local">本地</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="form.sourceType === 'remote'" label="URL">
          <el-input v-model="form.url" placeholder="订阅链接" />
        </el-form-item>
        <el-form-item v-if="form.sourceType === 'remote'" label="定时更新">
          <el-input v-model="form.updateCron" placeholder="cron 表达式，例如 0 0 * * *（留空则不定时更新）" />
          <div v-if="form.updateCron && !cronValid" class="field-hint field-hint-error">
            格式不正确，应为标准 5 段 cron：分 时 日 月 周，例如 0 0 * * *（每天 0 点）
          </div>
          <div v-else class="field-hint">
            按 cron 表达式定时重新拉取该订阅并缓存结果；留空表示每次读取都是实时拉取
          </div>
        </el-form-item>
        <el-form-item v-else label="内容">
          <div class="code-editor">
            <div class="code-gutter" ref="gutterRef">
              <div v-for="n in contentLineCount" :key="n" class="code-line-no">{{ n }}</div>
            </div>
            <textarea
              ref="textareaRef"
              v-model="form.content"
              class="code-textarea"
              placeholder="本地订阅内容"
              spellcheck="false"
              @scroll="syncGutterScroll"
            ></textarea>
          </div>
        </el-form-item>
        <el-form-item label="User-Agent">
          <el-input v-model="form.ua" placeholder="自定义 UA（可选）" />
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
import { ref, computed, onMounted } from 'vue'
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
const textareaRef = ref(null)
const gutterRef = ref(null)

const contentLineCount = computed(() => {
  const text = form.value.content || ''
  return Math.max(1, text.split('\n').length)
})

// Lightweight client-side check for standard 5-field cron syntax
// (minute hour day month weekday). Mirrors the backend's parser closely
// enough to give immediate feedback; the backend is the source of truth.
function isValidCron(expr) {
  const fields = expr.trim().split(/\s+/)
  if (fields.length !== 5) return false
  const bounds = [
    [0, 59],
    [0, 23],
    [1, 31],
    [1, 12],
    [0, 6],
  ]
  return fields.every((field, i) => {
    const [lo, hi] = bounds[i]
    return field.split(',').every((part) => {
      if (part === '') return false
      let base = part
      if (part.includes('/')) {
        const [b, step] = part.split('/')
        base = b
        if (!/^\d+$/.test(step) || Number(step) <= 0) return false
      }
      if (base === '*') return true
      if (base.includes('-')) {
        const [a, b] = base.split('-')
        if (!/^\d+$/.test(a) || !/^\d+$/.test(b)) return false
        const av = Number(a)
        const bv = Number(b)
        return av >= lo && bv <= hi && av <= bv
      }
      if (!/^\d+$/.test(base)) return false
      const v = Number(base)
      return v >= lo && v <= hi
    })
  })
}

const cronValid = computed(() => isValidCron(form.value.updateCron || '*'))

function syncGutterScroll() {
  if (gutterRef.value && textareaRef.value) {
    gutterRef.value.scrollTop = textareaRef.value.scrollTop
  }
}

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
  return { name: '', sourceType: 'remote', url: '', updateCron: '', ua: '', content: '', processText: '' }
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
    sourceType: row.source === 'local' ? 'local' : 'remote',
    url: row.url || '',
    updateCron: row.updateCron || '',
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
  if (form.value.sourceType === 'local' && !form.value.content) {
    ElMessage.warning('请输入本地订阅内容')
    return
  }
  if (form.value.sourceType === 'remote' && !form.value.url) {
    ElMessage.warning('请输入订阅链接')
    return
  }
  if (form.value.sourceType === 'remote' && form.value.updateCron && !cronValid.value) {
    ElMessage.warning('定时更新表达式格式不正确')
    return
  }
  saving.value = true
  try {
    const data = { ...form.value, process: parseProcess(form.value.processText) }
    delete data.processText
    delete data.sourceType
    data.source = form.value.sourceType
    if (form.value.sourceType === 'local') {
      data.url = ''
      data.updateCron = ''
    } else {
      data.content = ''
    }
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
.field-hint {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 4px;
  line-height: 1.5;
}
.field-hint-error {
  color: #f56c6c;
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
.code-editor {
  display: flex;
  width: 100%;
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-sm);
  overflow: hidden;
  background: var(--bg-surface);
}
.code-gutter {
  flex: 0 0 auto;
  min-width: 36px;
  padding: 8px 8px 8px 0;
  text-align: right;
  background: var(--bg-soft);
  color: var(--text-muted);
  font-family: ui-monospace, SFMono-Regular, Consolas, Menlo, monospace;
  font-size: 12px;
  line-height: 1.6;
  user-select: none;
  overflow: hidden;
  height: 180px;
}
.code-line-no {
  height: 19.2px;
}
.code-textarea {
  flex: 1 1 auto;
  height: 180px;
  padding: 8px 10px;
  border: none;
  outline: none;
  resize: none;
  font-family: ui-monospace, SFMono-Regular, Consolas, Menlo, monospace;
  font-size: 12px;
  line-height: 1.6;
  color: var(--text-body);
  background: transparent;
}
</style>
