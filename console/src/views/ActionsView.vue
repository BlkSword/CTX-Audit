<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import type { ActionSpec, ActionResult } from '../api'

const route = useRoute()
const workspaceId = computed(() => String(route.params.id ?? ''))
const specs = ref<ActionSpec[]>([])
const activeId = ref<string | null>(null)
const values = ref<Record<string, string>>({})
const result = ref<ActionResult | null>(null)
const busy = ref(false)

const active = computed(() => specs.value.find((s) => s.id === activeId.value) ?? null)

function select(spec: ActionSpec) {
  activeId.value = spec.id
  result.value = null
  const next: Record<string, string> = {}
  for (const a of spec.args) next[a.name] = ''
  values.value = next
}

async function run() {
  if (!active.value) return
  busy.value = true
  result.value = null
  try {
    const r = await api.runAction(workspaceId.value, active.value.id, values.value)
    result.value = r
    if (r.ok) {
      ElMessage.success('动作执行完成')
      // Persist the outcome as session evidence so it survives a reload.
      void api
        .addActionEvidence(workspaceId.value, {
          action: active.value.id,
          summary: JSON.stringify(r.data ?? r.stdout ?? '').slice(0, 2000),
        })
        .catch(() => {})
    } else {
      ElMessage.error(r.error ?? r.stderr ?? '执行失败')
    }
  } finally {
    busy.value = false
  }
}

onMounted(async () => {
  const r = await api.actions()
  if (r.ok) {
    specs.value = r.actions ?? []
    if (specs.value.length > 0) select(specs.value[0])
  }
})
</script>

<template>
  <div class="split">
    <div class="panel">
      <div class="panel-head">
        <div class="panel-title">动作目录 · {{ specs.length }}</div>
      </div>
      <div class="panel-body flush">
        <button
          v-for="s in specs"
          :key="s.id"
          class="action-item"
          :class="{ active: activeId === s.id }"
          @click="select(s)"
        >
          <div class="action-label">{{ s.label }}</div>
          <div class="action-desc">{{ s.description }}</div>
        </button>
      </div>
    </div>

    <div class="stack" v-if="active">
      <div class="panel">
        <div class="panel-head">
          <div>
            <div class="panel-title">{{ active.label }}</div>
            <div class="panel-sub">{{ active.description }}</div>
          </div>
          <el-button type="primary" size="small" :loading="busy" @click="run">执行</el-button>
        </div>
        <div class="panel-body">
          <el-form v-if="active.args.length" label-position="top">
            <el-form-item v-for="a in active.args" :key="a.name" :label="`${a.name}${a.required ? ' *' : ''}`">
              <el-input v-model="values[a.name]" :placeholder="a.hint" size="small" />
            </el-form-item>
          </el-form>
          <div v-else class="hint">该动作无需参数。</div>
        </div>
      </div>

      <div class="panel" v-if="result">
        <div class="panel-head">
          <div class="panel-title">执行结果</div>
          <span class="chip" :class="result.ok ? 'ok' : 'danger'">{{ result.ok ? 'OK' : 'FAILED' }}</span>
        </div>
        <div class="panel-body">
          <pre class="result-json mono">{{ JSON.stringify(result.data ?? result.stdout ?? result.error, null, 2) }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.split {
  display: grid;
  grid-template-columns: 300px minmax(0, 1fr);
  gap: 14px;
  align-items: start;
}
.action-item {
  display: block;
  width: 100%;
  text-align: left;
  padding: 10px 12px;
  background: transparent;
  border: none;
  border-bottom: 1px solid var(--rule-faint);
  border-left: 2px solid transparent;
  color: var(--text-2);
  font: inherit;
  cursor: pointer;
}
.action-item:hover {
  background: var(--surface-2);
}
.action-item.active {
  background: var(--accent-soft);
  border-left-color: var(--accent);
}
.action-label {
  font-size: var(--fs-sm);
  font-weight: 600;
  color: var(--text);
}
.action-desc {
  font-size: var(--fs-xs);
  color: var(--text-3);
  margin-top: 2px;
  line-height: 1.5;
}
.result-json {
  font-size: 10.5px;
  line-height: 1.6;
  color: var(--text-2);
  background: var(--bg-elevated);
  border: 1px solid var(--rule-faint);
  border-radius: var(--r-md);
  padding: 12px;
  max-height: 520px;
  overflow: auto;
  margin: 0;
}
@media (max-width: 1100px) {
  .split {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
