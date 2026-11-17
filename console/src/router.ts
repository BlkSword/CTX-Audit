import { createRouter, createWebHashHistory } from 'vue-router'

/**
 * Hash history keeps the console working under both mounts: the standalone
 * server serves it at `/`, the editor plugin mounts it at `/console`, and a
 * history-mode router would need server-side rewrites in both.
 */
export const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', redirect: '/workspaces' },
    {
      path: '/workspaces',
      name: 'workspaces',
      component: () => import('./views/WorkspacePicker.vue'),
      meta: { title: '工作区' },
    },
    {
      path: '/w/:id',
      component: () => import('./views/WorkspaceShell.vue'),
      children: [
        { path: '', redirect: (to) => `/w/${String(to.params.id ?? '')}/overview` },
        {
          path: 'overview',
          name: 'overview',
          component: () => import('./views/OverviewView.vue'),
          meta: { title: '总览' },
        },
        {
          path: 'sessions',
          name: 'sessions',
          component: () => import('./views/SessionsView.vue'),
          meta: { title: '审计会话' },
        },
        {
          path: 'coverage',
          name: 'coverage',
          component: () => import('./views/CoverageView.vue'),
          meta: { title: '覆盖与待审' },
        },
        {
          path: 'chains',
          name: 'chains',
          component: () => import('./views/ChainsView.vue'),
          meta: { title: '候选链' },
        },
        {
          path: 'payload',
          name: 'payload',
          component: () => import('./views/PayloadView.vue'),
          meta: { title: '载荷档位' },
        },
        {
          path: 'actions',
          name: 'actions',
          component: () => import('./views/ActionsView.vue'),
          meta: { title: '能力动作' },
        },
        {
          path: 'gate',
          name: 'gate',
          component: () => import('./views/GateView.vue'),
          meta: { title: '漂移闸门' },
        },
        {
          path: 'report',
          name: 'report',
          component: () => import('./views/ReportView.vue'),
          meta: { title: '报告' },
        },
        {
          path: 'assistant',
          name: 'assistant',
          component: () => import('./views/AssistantView.vue'),
          meta: { title: '审计助手' },
        },
      ],
    },
  ],
})
