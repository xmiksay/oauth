# Security policy

## Reporting a vulnerability

Please **do not** open a public issue, pull request or discussion for a
security problem. Report it privately through GitHub's security advisories:
**[Report a vulnerability](https://github.com/xmiksay/oauth/security/advisories/new)**
(repository *Security* tab → *Report a vulnerability*).

Include what you can: the affected version or commit, the component (OIDC
endpoints, sign-in, federation, passkeys, management API, tenant isolation,
SPA), steps to reproduce or a proof of concept, and the impact you expect.
Never include real users' data or secrets; test against your own instance.

## Supported versions

Only the **latest release** (the newest `vX.Y.Z` tag, image
`ghcr.io/xmiksay/oauth:X.Y.Z`) receives security fixes. Fixes land on `main`
first and ship in a new release; older releases are not patched. `:main` and
`:sha-…` images are development builds.

## What to expect

- **Acknowledgement** within 3 working days.
- **Assessment** (confirmed or not, severity) within 10 working days.
- **Fix**: critical and high severity issues are worked on immediately and
  released as soon as a fix is ready; others go into the next release. You get
  progress updates in the advisory at least every 14 days.
- **Disclosure**: the advisory is published (with a CVE where appropriate)
  once the fixed release is out, normally within 90 days of the report.
  Reporters are credited unless they ask not to be.

This is a project maintained by one person on a best-effort basis; there is
no bug bounty.

## Security review status

The project has **not yet had an independent security review**. An external
penetration test / code audit is planned and must happen before third-party
production use: [#43](https://github.com/xmiksay/oauth/issues/43).
Until then, treat deployments for third parties as at your own risk.
