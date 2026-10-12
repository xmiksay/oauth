export interface AdminNavItem {
  name: string
  path: string
  label: string
}

/** Left-nav entries of the admin portal; each becomes a child route of `/:tenant/admin`. */
export const adminNav: AdminNavItem[] = [
  { name: 'admin-users', path: 'users', label: 'Users' },
  { name: 'admin-groups', path: 'groups', label: 'Groups' },
  { name: 'admin-apps', path: 'app-registrations', label: 'App registrations' },
  { name: 'admin-role-assignments', path: 'role-assignments', label: 'Role assignments' },
  { name: 'admin-directory-roles', path: 'directory-roles', label: 'Directory roles' },
  { name: 'admin-audit', path: 'audit-log', label: 'Audit log' },
  { name: 'admin-settings', path: 'settings', label: 'Settings' },
]
