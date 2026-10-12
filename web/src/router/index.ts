import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { useTenantStore } from '@/stores/tenant'
import { adminNav } from '@/areas/admin/nav'

const ComingSoon = () => import('@/components/ComingSoon.vue')
const AuthCallback = () => import('@/components/AuthCallback.vue')

const routes: RouteRecordRaw[] = [
  {
    path: '/:tenant/login',
    name: 'login',
    component: () => import('@/areas/login/LoginPage.vue'),
  },
  {
    path: '/:tenant/myaccount/callback',
    name: 'myaccount-callback',
    component: AuthCallback,
  },
  {
    path: '/:tenant/myaccount',
    name: 'myaccount',
    component: () => import('@/areas/myaccount/MyAccountPage.vue'),
  },
  {
    path: '/:tenant/admin/callback',
    name: 'admin-callback',
    component: AuthCallback,
  },
  {
    path: '/:tenant/admin',
    component: () => import('@/areas/admin/AdminLayout.vue'),
    children: [
      { path: '', name: 'admin', component: () => import('@/areas/admin/AdminHome.vue') },
      ...adminNav.map((item) => ({
        path: item.path,
        name: item.name,
        component: ComingSoon,
        meta: { title: item.label },
      })),
    ],
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('@/components/NotFound.vue'),
  },
]

export const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
})

router.beforeEach((to) => {
  useTenantStore().setFromParam(to.params.tenant)
})
