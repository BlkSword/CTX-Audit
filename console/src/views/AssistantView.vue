<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { useWorkspaceStore } from '../store'
import type { AuditSession } from '../api'

const store = useWorkspaceStore()
const route = useRoute()
const workspaceId = computed(() => String(route.params.id ?? ''))
const workspacePath = computed(() => store.active.value?.path ?? '')

const text = ref('')
const busy = ref(false)
const sessionId = ref<string | null>(null)
const available = ref<boolean | null>(null)
const replies = ref<Array<{ at?: number; text: string; kind?: 'assistant' | 'tool'; tool?: string }>>([])
const lastResult = ref<{ ok: boolean; created?: boolean; fallback?: boolean; error?: string } | null>(null)
let timer: number | null = null

const overview = computed(() => store.overview.value)

function buildBrief(): string {
  const o = overview.value
  if (!o) return '# CTX-Audit 审计简报\n\n（尚未生成总览）\n'
  const lines = [
    '# CTX-Audit 审计简报',
    '',
    `工作区：\`${o.workspace.path}\``,
    '',
    '## 覆盖',
    `- 端点 ${o.coverage.methodRoutes}，未覆盖 ${o.coverage.uncovered}，置信 ${o.coverage.confidence}`,
    `- 注解覆盖 ${o.coverage.annotationCovered}，文件 ${o.coverage.filesIndexed}`,
    '',
    '## 候选链',
    `- 共 ${o.chains.total} 条`,
  ]
  for (const [tier, count] of Object.entries(o.chains.tiers)) {
    lines.push(`  - ${tier}: ${count}`)
  }
  if (o.chains.top.length > 0) {
    lines.push('', '## 头部链')
    for (const c of o.chains.top.slice(0, 5)) {
      lines.push(`- \`${c.chainId}\` ${c.tier} · ${c.sinkKind} @ ${c.sinkFile}:${c.sinkLine}`)
    }
  }
  lines.push('', '请基于以上事实给出判定与下一步建议；引用证据时请写证据 ID。')
  return lines.join('\n')
}

async function appendSessionEvidence() {
  try {
    const r = await api.sessions(workspaceId.value)
    const list: AuditSession[] = r.sessions ?? []
    const latest = list.find((s) => s.status === 'done') ?? list[0]
    if (!latest) {
      ElMessage.warning('该工作区还没有审计会话，请先在总览页点「一键审计」。')
      return
    }
    const rows = latest.evidence.slice(0, 40).map((e) => {
      const summary = (e.summary ?? e.kind).split('|').join('\\|')
      return `| \`${e.id}\` | ${e.stage} | ${summary} |`
    })
    const lines = [
      '',
      `## 审计会话证据（${latest.id} · ${latest.label}）`,
      '',
      '| 证据 ID | 阶段 | 摘要 |',
      '| --- | --- | --- |',
      ...rows,
    ]
    if (latest.evidence.length > 40) {
      lines.push('', `> 仅列出前 40 条，共 ${latest.evidence.length} 条`)
    }
    lines.push('', '引用这些证据时请直接写证据 ID（如 `EV-payload-1`），不要改写其内容。')
    text.value = `${text.value}\n${lines.join('\n')}\n`
  } catch (e) {
    ElMessage.error(String(e))
  }
}

async function send() {
  if (!text.value.trim()) return
  busy.value = true
  lastResult.value = null
  try {
    const r = (await api.agentPrompt(workspacePath.value, text.value)) as {
      ok: boolean
      sessionId?: string
      created?: boolean
      fallback?: boolean
      error?: string
    }
    lastResult.value = r
    if (r.ok) {
      sessionId.value = r.sessionId ?? null
      if (r.fallback) {
        void navigator.clipboard?.writeText(text.value)
        ElMessage.warning('网关未接受自动投递，简报已复制到剪贴板')
      } else {
        ElMessage.success(r.created ? '已创建会话并发送' : '已发送到既有会话')
      }
    }
  } catch (e) {
    lastResult.value = { ok: false, error: String(e) }
  } finally {
    busy.value = false
  }
}

async function poll() {
  if (!sessionId.value) return
  try {
    const r = await api.agentStatus(workspacePath.value, true)
    if (r.replies) replies.value = r.replies
  } catch {
    /* transient */
  }
}

onMounted(async () => {
  text.value = buildBrief()
  try {
    const r = await api.agentStatus(workspacePath.value)
    available.value = r.available ?? true
    sessionId.value = r.sessionId ?? null
  } catch {
    available.value = false
  }
  timer = window.setInterval(poll, 6000)
})

onUnmounted(() => {
  if (timer !== null) window.clearInterval(timer)
})
</script>

<template>
  <div class="stack">
    <div class="panel">
      <div class="panel-head">
        <div>
          <div class="panel-title">审计助手</div>
          <div class="panel-sub">
            把审计简报发给绑定该工作区的 Agent 会话，并回读它的推理与工具调用
          </div>
        </div>
        <span class="chip" :class="available === false ? 'danger' : available ? 'ok' : 'warn'">
          {{ available === false ? 'UNAVAILABLE' : available ? 'READY' : 'CHECKING' }}
        </span>
      </div>
      <div class="panel-body">
        <el-input
          v-model="text"
          type="textarea"
          :rows="14"
          placeholder="审计简报…"
          class="brief-input"
        />
        <div class="row wrap" style="margin-top: 10px">
          <el-button type="primary" size="small" :loading="busy" :disabled="!text.trim()" @click="send">
            发送给 Agent
          </el-button>
          <el-button size="small" @click="text = buildBrief()">重置为最新简报</el-button>
          <el-button size="small" @click="appendSessionEvidence">附上会话证据</el-button>
          <span v-if="lastResult?.ok" class="chip ok">
            {{ lastResult.created ? '已创建会话' : '已发送' }}
          </span>
          <span v-if="lastResult?.error" class="chip danger">{{ lastResult.error }}</span>
        </div>
      </div>
    </div>

    <div class="panel" v-if="replies.length">
      <div class="panel-head">
        <div class="panel-title">Agent 回复 · {{ replies.length }}</div>
        <el-button size="small" text @click="poll">刷新</el-button>
      </div>
      <div class="panel-body">
        <div class="logpane">
          <div v-for="(r, i) in replies" :key="i">
            <div class="log-meta">
              {{ r.at ? new Date(r.at).toLocaleTimeString() : `#${i + 1}` }}
              <span v-if="r.kind === 'tool'"> · TOOL {{ r.tool }}</span>
              <span v-else> · AGENT</span>
            </div>
            <div class="log-entry" :class="r.kind === 'tool' ? 'tool' : 'agent'">
              {{ r.kind === 'tool' ? `→ ${r.text}` : r.text }}
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-else class="empty">
      <div class="empty-title">还没有 Agent 回复</div>
      <div class="hint">发送简报后，Agent 的推理与工具调用会显示在这里。</div>
    </div>
  </div>
</template>

<style scoped>
.brief-input :deep(.el-textarea__inner) {
  font-family: var(--font-mono);
  font-size: 11.5px;
  line-height: 1.6;
}
</style>
