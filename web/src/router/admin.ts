import type { RouteRecordRaw } from 'vue-router'

/** Children of `/admin`; list routes match `adminNav` names. */
export const adminRoutes: RouteRecordRaw[] = [
  {
    path: '',
    name: 'admin',
    component: () => import('@/areas/admin/AdminHome.vue'),
    meta: { title: 'Overview' },
  },
  {
    path: 'users',
    name: 'admin-users',
    component: () => import('@/areas/admin/users/UsersList.vue'),
    meta: { title: 'Users' },
  },
  {
    path: 'users/:id',
    name: 'admin-user',
    component: () => import('@/areas/admin/users/UserDetail.vue'),
    meta: { title: 'User' },
  },
  {
    path: 'groups',
    name: 'admin-groups',
    component: () => import('@/areas/admin/groups/GroupsList.vue'),
    meta: { title: 'Groups' },
  },
  {
    path: 'groups/:id',
    name: 'admin-group',
    component: () => import('@/areas/admin/groups/GroupDetail.vue'),
    meta: { title: 'Group' },
  },
  {
    path: 'app-registrations',
    name: 'admin-apps',
    component: () => import('@/areas/admin/apps/AppsList.vue'),
    meta: { title: 'App registrations' },
  },
  {
    path: 'app-registrations/:id',
    component: () => import('@/areas/admin/apps/AppDetail.vue'),
    meta: { title: 'App registration' },
    children: [
      {
        path: '',
        name: 'admin-app',
        component: () => import('@/areas/admin/apps/AppOverview.vue'),
      },
      {
        path: 'authentication',
        name: 'admin-app-auth',
        component: () => import('@/areas/admin/apps/AppAuthentication.vue'),
      },
      {
        path: 'secrets',
        name: 'admin-app-secrets',
        component: () => import('@/areas/admin/apps/AppSecrets.vue'),
      },
      {
        path: 'token',
        name: 'admin-app-token',
        component: () => import('@/areas/admin/apps/AppTokenConfig.vue'),
      },
      {
        path: 'expose',
        name: 'admin-app-expose',
        component: () => import('@/areas/admin/apps/AppExposeApi.vue'),
      },
      {
        path: 'roles',
        name: 'admin-app-roles',
        component: () => import('@/areas/admin/apps/AppRoles.vue'),
      },
      {
        path: 'permissions',
        name: 'admin-app-permissions',
        component: () => import('@/areas/admin/apps/AppPermissions.vue'),
      },
    ],
  },
  {
    path: 'role-assignments',
    name: 'admin-role-assignments',
    component: () => import('@/areas/admin/access/RoleAssignments.vue'),
    meta: { title: 'Role assignments' },
  },
  {
    path: 'directory-roles',
    name: 'admin-directory-roles',
    component: () => import('@/areas/admin/access/DirectoryRoles.vue'),
    meta: { title: 'Directory roles' },
  },
  {
    path: 'audit-log',
    name: 'admin-audit',
    component: () => import('@/areas/admin/access/AuditLog.vue'),
    meta: { title: 'Audit log' },
  },
  {
    path: 'settings',
    name: 'admin-settings',
    component: () => import('@/areas/admin/access/TenantSettings.vue'),
    meta: { title: 'Settings' },
  },
  {
    path: 'tenants',
    name: 'admin-tenants',
    component: () => import('@/areas/admin/access/TenantsPage.vue'),
    meta: { title: 'Tenants' },
  },
]
