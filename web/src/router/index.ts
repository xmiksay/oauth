import {
  createRouter,
  createWebHistory,
  type RouteLocationNormalized,
  type RouteRecordRaw,
} from 'vue-router'
import { useTenantStore } from '@/stores/tenant'
import { useAuthStore } from '@/stores/auth'
import type { SpaArea } from '@/auth/oidc'
import { adminRoutes } from './admin'

declare module 'vue-router' {
  interface RouteMeta {
    /** Signed-in area (OIDC client) the route belongs to. */
    area?: SpaArea
    /** The OIDC redirect target: must not itself trigger a sign-in. */
    callback?: boolean
    title?: string
  }
}

const AuthCallback = () => import('@/components/AuthCallback.vue')

const routes: RouteRecordRaw[] = [
  {
    path: '/:tenant/login',
    name: 'login',
    component: () => import('@/areas/login/LoginPage.vue'),
    meta: { title: 'Sign in' },
  },
  {
    path: '/:tenant/logout',
    name: 'logout',
    component: () => import('@/areas/logout/LogoutPage.vue'),
    meta: { title: 'Sign out' },
  },
  {
    path: '/:tenant/myaccount/callback',
    name: 'myaccount-callback',
    component: AuthCallback,
    meta: { area: 'myaccount', callback: true },
  },
  {
    path: '/:tenant/myaccount',
    component: () => import('@/areas/myaccount/MyAccountLayout.vue'),
    meta: { area: 'myaccount' },
    children: [
      {
        path: '',
        name: 'myaccount',
        component: () => import('@/areas/myaccount/ProfilePage.vue'),
        meta: { title: 'Profile' },
      },
      {
        path: 'security',
        name: 'myaccount-security',
        component: () => import('@/areas/myaccount/SecurityPage.vue'),
        meta: { title: 'Security info' },
      },
      {
        path: 'sessions',
        name: 'myaccount-sessions',
        component: () => import('@/areas/myaccount/SessionsPage.vue'),
        meta: { title: 'Devices & sessions' },
      },
      {
        path: 'apps',
        name: 'myaccount-apps',
        component: () => import('@/areas/myaccount/AppsPage.vue'),
        meta: { title: 'App permissions' },
      },
    ],
  },
  {
    path: '/:tenant/admin/callback',
    name: 'admin-callback',
    component: AuthCallback,
    meta: { area: 'admin', callback: true },
  },
  {
    path: '/:tenant/admin',
    component: () => import('@/areas/admin/AdminLayout.vue'),
    meta: { area: 'admin' },
    children: adminRoutes,
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('@/components/NotFound.vue'),
    meta: { title: 'Page not found' },
  },
]

export const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
})

router.beforeEach(async (to) => {
  const tenants = useTenantStore()
  tenants.setFromParam(to.params.tenant)
  const area = to.meta.area
  if (!area || to.meta.callback || !tenants.slug) return true
  // false = the browser is already on its way to the authorize endpoint.
  return useAuthStore().ensureSignedIn(tenants.slug, area, to.fullPath)
})

const AREA_NAMES: Record<SpaArea, string> = { admin: 'Admin center', myaccount: 'My Account' }

/** "Users · Admin center · contoso" — child meta wins over the parent's. */
export function pageTitle(to: Pick<RouteLocationNormalized, 'meta' | 'params'>): string {
  const area = to.meta.area ? AREA_NAMES[to.meta.area] : null
  const tenant = typeof to.params.tenant === 'string' ? to.params.tenant : null
  return [to.meta.title, area, tenant].filter(Boolean).join(' · ') || 'oauth'
}

router.afterEach((to) => {
  document.title = pageTitle(to)
})
