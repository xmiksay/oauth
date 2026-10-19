export interface AdminNavItem {
  name: string
  path: string
  label: string
  /** Only in the `system` tenant (system Global Admins manage tenants there). */
  systemOnly?: boolean
}

/** Left-nav entries of the admin portal; each is a child route of `/admin`. */
export const adminNav: AdminNavItem[] = [
  { name: 'admin-users', path: 'users', label: 'Users' },
  { name: 'admin-groups', path: 'groups', label: 'Groups' },
  { name: 'admin-apps', path: 'app-registrations', label: 'App registrations' },
  { name: 'admin-identity-providers', path: 'identity-providers', label: 'Identity providers' },
  { name: 'admin-role-assignments', path: 'role-assignments', label: 'Role assignments' },
  { name: 'admin-directory-roles', path: 'directory-roles', label: 'Directory roles' },
  { name: 'admin-audit', path: 'audit-log', label: 'Audit log' },
  { name: 'admin-settings', path: 'settings', label: 'Settings' },
  { name: 'admin-tenants', path: 'tenants', label: 'Tenants', systemOnly: true },
]

export const SYSTEM_TENANT = 'system'
