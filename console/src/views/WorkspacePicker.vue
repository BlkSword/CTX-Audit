<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useWorkspaceStore } from '../store'

const store = useWorkspaceStore()
const router = useRouter()
const dialog = ref(false)
const newPath = ref('')
const newName = ref('')
const busy = ref(false)

onMounted(async () => {
  await store.loadWorkspaces()
})

async function add() {
  if (!newPath.value.trim()) return
  busy.value = true
  const ws = await store.addWorkspace(newPath.value.trim(), newName.value.trim() || undefined)
  busy.value = false
  if (ws) {
    dialog.value = false
    newPath.value = ''
    newName.value = ''
    ElMessage.success(`已添加工作区 ${ws.name}`)
    router.push(`/w/${ws.id}/overview`)
  } else {
    ElMessage.error(store.error.value ?? '添加失败')
  }
}

async function remove(id: string, name: string) {
  try {
    await ElMessageBox.confirm(`移除工作区「${name}」？审计记录会保留在本地。`, '确认移除', {
      type: 'warning',
      confirmButtonText: '移除',
      cancelButtonText: '取消',
    })
  } catch {
    return
  }
  await store.removeWorkspace(id)
}

function open(id: string) {
  router.push(`/w/${id}/overview`)
}
</script>

<template>
  <div class="picker">
    <header class="picker-head">
      <div>
        <div class="picker-title">CTX-Audit 审计控制台</div>
        <div class="picker-sub">选择一个工作区开始审计，或添加新的项目目录。</div>
      </div>
      <el-button type="primary" @click="dialog = true">添加工作区</el-button>
    </header>

    <div v-if="store.workspaces.value.length === 0" class="empty">
      <div class="empty-title">还没有工作区</div>
      <div class="hint">添加一个本地项目目录，控制台会为它建立索引与审计记录。</div>
      <el-button type="primary" style="margin-top: 12px" @click="dialog = true">添加工作区</el-button>
    </div>

    <div v-else class="grid">
      <div
        v-for="ws in store.workspaces.value"
        :key="ws.id"
        class="ws-card"
        @click="open(ws.id)"
      >
        <div class="ws-card-head">
          <div class="ws-card-name">{{ ws.name }}</div>
          <el-button
            size="small"
            text
            type="danger"
            @click.stop="remove(ws.id, ws.name)"
          >
            移除
          </el-button>
        </div>
        <div class="ws-card-path mono">{{ ws.path }}</div>
        <div class="ws-card-foot">
          <span class="chip">添加于 {{ new Date(ws.addedAt).toLocaleDateString() }}</span>
          <span class="ws-open">进入 →</span>
        </div>
      </div>
    </div>

    <el-dialog v-model="dialog" title="添加工作区" width="520px">
      <el-form label-position="top">
        <el-form-item label="项目路径（绝对路径）">
          <el-input v-model="newPath" placeholder="C:\\path\\to\\project" />
        </el-form-item>
        <el-form-item label="显示名称（可选）">
          <el-input v-model="newName" placeholder="留空则使用目录名" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog = false">取消</el-button>
        <el-button type="primary" :loading="busy" @click="add">添加</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.picker {
  max-width: 1080px;
  margin: 0 auto;
  padding: 40px 24px;
}
.picker-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 20px;
  margin-bottom: 24px;
}
.picker-title {
  font-size: var(--fs-2xl);
  font-weight: 600;
  letter-spacing: -0.02em;
}
.picker-sub {
  font-size: var(--fs-sm);
  color: var(--text-3);
  margin-top: 5px;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 12px;
}
.ws-card {
  padding: 14px;
  background: var(--surface);
  border: 1px solid var(--rule);
  border-radius: var(--r-lg);
  cursor: pointer;
  transition: border-color 0.12s ease;
}
.ws-card:hover {
  border-color: var(--accent-line);
}
.ws-card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.ws-card-name {
  font-size: var(--fs-lg);
  font-weight: 600;
}
.ws-card-path {
  font-size: var(--fs-xs);
  color: var(--text-3);
  margin: 6px 0 12px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.ws-card-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.ws-open {
  font-size: var(--fs-sm);
  color: var(--accent);
}
</style>
