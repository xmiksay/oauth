//! When bootstrapping an *existing* app needs `--adopt-app` (#97): holding a
//! provisioning role says nothing about who made the app — an admin or
//! `oauth apply` may have given it to a third-party app.

use super::provisioning::Role;

/// Why an existing app needs `--adopt-app`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Takeover {
    /// It holds no management API provisioning role.
    NoRole,
    /// It holds only `Directory.Read.All` and read-write is requested.
    Upgrade,
    /// It holds `Directory.ReadWrite.All`, read is requested and bootstrap
    /// did not make it.
    Downgrade,
    /// `--rotate-secret` for an app bootstrap did not make.
    RotateSecret,
}

/// What bootstrap knows about an existing app.
#[derive(Clone, Copy, Debug)]
pub struct Held {
    pub requested: bool,
    pub other: bool,
    /// It carries a secret described [`super::provisioning::SECRET_DESCRIPTION`]:
    /// bootstrap made or adopted it. A guard against typos, not a security
    /// boundary — whoever can add a secret to an app already controls it.
    pub bootstrap_marker: bool,
}

/// `None`: bootstrap may go ahead without `--adopt-app`.
pub fn takeover(requested: Role, held: Held, rotate_secret: bool) -> Option<Takeover> {
    if !held.requested && !held.other {
        return Some(Takeover::NoRole);
    }
    // Widening is never routine, marker or not.
    if requested == Role::ReadWrite && !held.requested {
        return Some(Takeover::Upgrade);
    }
    if held.bootstrap_marker {
        return None;
    }
    if requested == Role::Read && held.other {
        return Some(Takeover::Downgrade);
    }
    rotate_secret.then_some(Takeover::RotateSecret)
}

#[cfg(test)]
mod tests {
    use super::{Held, Role, Takeover, takeover};

    fn held(requested: bool, other: bool, bootstrap_marker: bool) -> Held {
        Held {
            requested,
            other,
            bootstrap_marker,
        }
    }

    #[test]
    fn no_role_and_upgrade_always_need_the_flag() {
        for marker in [false, true] {
            for role in [Role::Read, Role::ReadWrite] {
                let t = takeover(role, held(false, false, marker), false);
                assert_eq!(t, Some(Takeover::NoRole));
            }
            let t = takeover(Role::ReadWrite, held(false, true, marker), false);
            assert_eq!(t, Some(Takeover::Upgrade));
        }
    }

    #[test]
    fn downgrade_and_rotation_need_the_flag_without_the_marker() {
        let t = takeover(Role::Read, held(false, true, false), false);
        assert_eq!(t, Some(Takeover::Downgrade));
        let t = takeover(Role::Read, held(true, true, false), false);
        assert_eq!(t, Some(Takeover::Downgrade));
        let t = takeover(Role::Read, held(true, false, false), true);
        assert_eq!(t, Some(Takeover::RotateSecret));
        let t = takeover(Role::ReadWrite, held(true, false, false), true);
        assert_eq!(t, Some(Takeover::RotateSecret));
        assert_eq!(takeover(Role::Read, held(false, true, true), true), None);
        assert_eq!(
            takeover(Role::ReadWrite, held(true, false, true), true),
            None
        );
    }

    #[test]
    fn keeping_the_role_needs_no_flag() {
        for marker in [false, true] {
            assert_eq!(takeover(Role::Read, held(true, false, marker), false), None);
            let t = takeover(Role::ReadWrite, held(true, false, marker), false);
            assert_eq!(t, None);
            // Dropping the extra Read narrows a read-write app.
            let t = takeover(Role::ReadWrite, held(true, true, marker), false);
            assert_eq!(t, None);
        }
    }
}
