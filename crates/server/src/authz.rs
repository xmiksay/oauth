//! Management API authorization (pure): who may read / write which part of
//! the directory. Entra model:
//!
//! - Delegated callers act through their directory roles. Any directory role
//!   grants read access to the whole directory; members without one get no
//!   management access at all (only `me/…`). GlobalAdmin writes everything,
//!   UserAdmin users / groups / memberships, ApplicationAdmin app
//!   registrations and everything hanging off them (secrets, scopes, roles,
//!   required permissions, role assignments, consents).
//! - App-only callers act through the management API's app roles:
//!   `Directory.Read.All` reads, `Directory.ReadWrite.All` reads and writes —
//!   but never directory roles (no privilege escalation by an app).
//! - Directory roles are assigned by GlobalAdmins only; tenants are managed
//!   by GlobalAdmins of the system tenant only (see `api::tenants`).

use entity::enums::DirectoryRole;
use uuid::Uuid;

/// Part of the directory an endpoint touches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Area {
    /// Users, groups, group members.
    Directory,
    /// App registrations and their secrets / scopes / roles / required
    /// permissions, app role assignments, consent grants.
    Applications,
    DirectoryRoles,
    AuditLog,
    /// Upstream identity providers: any directory role reads, only a
    /// GlobalAdmin writes, and apps get neither (sign-in trust is not
    /// delegated to an app).
    IdentityProviders,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

/// An authenticated management API caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Principal {
    User { id: Uuid, roles: Vec<DirectoryRole> },
    App { id: Uuid, read: bool, write: bool },
}

impl Principal {
    pub fn has_role(&self, role: DirectoryRole) -> bool {
        matches!(self, Self::User { roles, .. } if roles.contains(&role))
    }

    pub fn is_global_admin(&self) -> bool {
        self.has_role(DirectoryRole::GlobalAdmin)
    }
}

pub fn allows(principal: &Principal, area: Area, access: Access) -> bool {
    match principal {
        Principal::User { roles, .. } => {
            if roles.contains(&DirectoryRole::GlobalAdmin) {
                return true;
            }
            match access {
                Access::Read => !roles.is_empty(),
                Access::Write => match area {
                    Area::Directory => roles.contains(&DirectoryRole::UserAdmin),
                    Area::Applications => roles.contains(&DirectoryRole::ApplicationAdmin),
                    Area::DirectoryRoles | Area::AuditLog | Area::IdentityProviders => false,
                },
            }
        }
        Principal::App { read, write, .. } => match (area, access) {
            (Area::IdentityProviders, _) => false,
            (_, Access::Read) => *read || *write,
            (_, Access::Write) => *write && matches!(area, Area::Directory | Area::Applications),
        },
    }
}

/// Administrators (GlobalAdmin, ApplicationAdmin) can only be modified —
/// updated, disabled, deleted, password / MFA reset, signed out — by a
/// GlobalAdmin: otherwise a UserAdmin or an app could take over a more
/// privileged account.
pub fn can_modify_user(principal: &Principal, target_roles: &[DirectoryRole]) -> bool {
    principal.is_global_admin()
        || !target_roles.iter().any(|r| {
            matches!(
                r,
                DirectoryRole::GlobalAdmin | DirectoryRole::ApplicationAdmin
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use Access::{Read, Write};
    use DirectoryRole::{ApplicationAdmin, GlobalAdmin, UserAdmin};

    fn user(roles: &[DirectoryRole]) -> Principal {
        Principal::User {
            id: Uuid::nil(),
            roles: roles.to_vec(),
        }
    }

    fn app(read: bool, write: bool) -> Principal {
        Principal::App {
            id: Uuid::nil(),
            read,
            write,
        }
    }

    const AREAS: [Area; 5] = [
        Area::Directory,
        Area::Applications,
        Area::DirectoryRoles,
        Area::AuditLog,
        Area::IdentityProviders,
    ];

    /// Expected read and write access per area, in [`AREAS`] order.
    fn check(p: &Principal, reads: [bool; 5], writes: [bool; 5]) {
        for ((area, read), write) in AREAS.into_iter().zip(reads).zip(writes) {
            assert_eq!(allows(p, area, Read), read, "{p:?} read {area:?}");
            assert_eq!(allows(p, area, Write), write, "{p:?} write {area:?}");
        }
    }

    #[test]
    fn permission_matrix() {
        let all = [true; 5];
        let none = [false; 5];
        // Apps never see identity providers.
        let app_reads = [true, true, true, true, false];
        check(&user(&[GlobalAdmin]), all, all);
        check(&user(&[UserAdmin]), all, [true, false, false, false, false]);
        check(
            &user(&[ApplicationAdmin]),
            all,
            [false, true, false, false, false],
        );
        check(
            &user(&[UserAdmin, ApplicationAdmin]),
            all,
            [true, true, false, false, false],
        );
        check(&user(&[]), none, none);
        check(&app(true, false), app_reads, none);
        check(
            &app(false, true),
            app_reads,
            [true, true, false, false, false],
        );
        check(
            &app(true, true),
            app_reads,
            [true, true, false, false, false],
        );
        check(&app(false, false), none, none);
    }

    #[test]
    fn administrators_are_protected_from_lesser_callers() {
        for target in [
            &[GlobalAdmin][..],
            &[ApplicationAdmin],
            &[UserAdmin, GlobalAdmin],
        ] {
            assert!(can_modify_user(&user(&[GlobalAdmin]), target));
            assert!(!can_modify_user(&user(&[UserAdmin]), target));
            assert!(!can_modify_user(&app(true, true), target));
        }
        for target in [&[][..], &[UserAdmin]] {
            assert!(can_modify_user(&user(&[UserAdmin]), target));
            assert!(can_modify_user(&app(false, true), target));
        }
    }
}
