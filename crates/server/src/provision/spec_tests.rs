//! Unit tests of the tenant file schema.

use super::*;

const FULL: &str = r"
tenant: contoso
users:
  - email: Alice@Example.com
    display_name: Alice
    password_env: OAUTH_APPLY_ALICE_PASSWORD
groups:
  - display_name: Engineers
    members: [alice@example.com]
applications:
  - client_id: api
    display_name: API
    identifier_uri: api://api
    scopes:
      - value: read
    roles:
      - value: Admin
        display_name: Admin
        allowed_member_types: [user, application]
  - client_id: web
    display_name: Web
    redirect_uris: [https://web.example/cb]
    required_permissions:
      - { resource: api, type: delegated, value: read }
role_assignments:
  - { resource: api, role: Admin, group: Engineers }
admin_consents:
  - { client: web, resource: api }
";

#[test]
fn parses_a_full_file() {
    let spec = parse(FULL).unwrap();
    assert_eq!(spec.tenant, "contoso");
    assert_eq!(spec.applications.len(), 2);
    let api = spec.applications.first().unwrap();
    assert_eq!(api.identifier_uri, Some(Some("api://api".into())));
    assert!(spec.identity_providers.is_empty());
    let web = spec.applications.get(1).unwrap();
    assert_eq!(web.identifier_uri, None);
    assert_eq!(web.body().redirect_uris.unwrap().len(), 1);
}

#[test]
fn the_documented_example_parses() {
    let spec = parse(include_str!("../../../../docs/examples/tenant.yaml")).unwrap();
    assert_eq!(spec.applications.len(), 4);
}

#[test]
fn explicit_null_clears() {
    let spec = parse(
        "tenant: t\napplications:\n  - { client_id: a, display_name: A, identifier_uri: null }\n",
    )
    .unwrap();
    assert_eq!(
        spec.applications.first().unwrap().identifier_uri,
        Some(None)
    );
}

#[test]
fn newer_app_and_idp_settings_reach_the_api_bodies() {
    let spec = parse(
        "tenant: t
applications:
  - { client_id: a, display_name: A, assignment_required: true }
identity_providers:
  - name: G
    kind: google
    client_id: g
    hosted_domain: example.com
    allowed_tenants: []
    trust_upstream_email: true
  - { name: O, issuer: https://o.example, client_id: o, hosted_domain: null }
",
    )
    .unwrap();
    let app = spec.applications.first().unwrap().body();
    assert_eq!(app.assignment_required, Some(true));
    let google = spec.identity_providers.first().unwrap().body(None);
    assert_eq!(google.kind.as_deref(), Some("google"));
    assert_eq!(google.issuer, None, "a preset's issuer defaults");
    assert_eq!(google.hosted_domain, Some(Some("example.com".into())));
    assert_eq!(google.allowed_tenants, Some(Vec::new()));
    assert_eq!(google.trust_upstream_email, Some(true));
    let oidc = spec.identity_providers.get(1).unwrap().body(None);
    assert_eq!(oidc.kind, None);
    assert_eq!(oidc.hosted_domain, Some(None), "null clears");
    let defaults =
        parse("tenant: t\napplications:\n  - { client_id: a, display_name: A }\n").unwrap();
    assert_eq!(
        defaults
            .applications
            .first()
            .unwrap()
            .body()
            .assignment_required,
        None
    );
}

#[test]
fn unknown_fields_are_rejected() {
    for bad in [
        "tenant: t\nfoo: 1\n",
        "tenant: t\nusers:\n  - { email: a@b.c, display_name: A, password: x }\n",
        "tenant: t\napplications:\n  - { client_id: a, display_name: A, client_secret: x }\n",
        "tenant: t\napplications:\n  - client_id: a\n    display_name: A\n    scopes: [{ value: r, extra: 1 }]\n",
    ] {
        assert!(parse(bad).is_err(), "{bad}");
    }
    assert!(parse("users: []\n").is_err(), "tenant is required");
}

#[test]
fn duplicates_are_rejected() {
    for (bad, what) in [
        (
            "tenant: t\nusers:\n  - { email: a@b.c, display_name: A }\n  - { email: A@B.C, display_name: B }\n",
            "duplicate user",
        ),
        (
            "tenant: t\ngroups:\n  - { display_name: Eng }\n  - { display_name: eng }\n",
            "duplicate group",
        ),
        (
            "tenant: t\napplications:\n  - client_id: a\n    display_name: A\n    scopes: [{ value: r }, { value: r }]\n",
            "duplicate scope",
        ),
        (
            "tenant: t\nadmin_consents:\n  - { client: a, resource: b }\n  - { client: a, resource: b, scopes: [] }\n",
            "duplicate admin consent",
        ),
        (
            "tenant: t\nidentity_providers:\n  - { name: Google, kind: google, client_id: a }\n  - { name: \" Google\", kind: google, client_id: b }\n",
            "duplicate identity provider",
        ),
    ] {
        let err = parse(bad).unwrap_err().to_string();
        assert!(err.contains(what), "{bad}: {err}");
    }
}

#[test]
fn assignments_need_exactly_one_principal() {
    for bad in [
        "tenant: t\nrole_assignments:\n  - { resource: a, role: R }\n",
        "tenant: t\nrole_assignments:\n  - { resource: a, role: R, user: u@x.y, group: G }\n",
    ] {
        assert!(parse(bad).unwrap_err().to_string().contains("exactly one"));
    }
}

#[test]
fn oversized_files_are_rejected() {
    let big = format!("tenant: t\n#{}\n", "x".repeat(MAX_FILE_BYTES));
    assert!(parse(&big).unwrap_err().to_string().contains("larger"));
}

#[test]
fn oversized_files_are_not_read_whole() {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"tenant: t\n").unwrap();
    assert_eq!(read_file(file.path()).unwrap(), "tenant: t\n");
    file.write_all(&vec![b'#'; MAX_FILE_BYTES]).unwrap();
    let err = read_file(file.path()).unwrap_err().to_string();
    assert!(err.contains("larger"), "{err}");
}

#[test]
fn back_channel_logout_and_id_token_groups_reach_the_app_body() {
    let spec = parse(
        "tenant: t
applications:
  - client_id: a
    display_name: A
    backchannel_logout_uri: https://a.example/bcl
    backchannel_logout_session_required: true
    id_token_groups: assigned
  - { client_id: b, display_name: B, backchannel_logout_uri: null }
  - { client_id: c, display_name: C }
",
    )
    .unwrap();
    let body = |i: usize| spec.applications.get(i).unwrap().body();
    let a = body(0);
    assert_eq!(
        a.backchannel_logout_uri,
        Some(Some("https://a.example/bcl".into()))
    );
    assert_eq!(a.backchannel_logout_session_required, Some(true));
    assert_eq!(a.id_token_groups.as_deref(), Some("assigned"));
    assert_eq!(body(1).backchannel_logout_uri, Some(None));
    let c = body(2);
    assert_eq!(c.backchannel_logout_uri, None);
    assert_eq!(c.backchannel_logout_session_required, None);
    assert_eq!(c.id_token_groups, None);
    // Strict schema: the API's own spelling only.
    let typo =
        "tenant: t\napplications:\n  - { client_id: a, display_name: A, backchannel_logout: x }\n";
    let err = format!("{:#}", parse(typo).unwrap_err());
    assert!(err.contains("unknown field"), "{err}");
}

#[test]
fn env_references_need_the_apply_prefix() {
    for var in [
        "OAUTH_MASTER_KEY",
        "DATABASE_URL",
        "SMTP_URL",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_WEBHOOK_SECRET",
        "OAUTH_APPLY_",
        "oauth_apply_x",
        "OAUTH_APPLY_a",
        "OAUTH_APPLY_X-Y",
        "PREFIX_OAUTH_APPLY_X",
    ] {
        let user = format!(
            "tenant: t\nusers:\n  - {{ email: a@b.c, display_name: A, password_env: \"{var}\" }}\n"
        );
        let idp = format!(
            "tenant: t\nidentity_providers:\n  - {{ name: I, issuer: https://i.example, client_id: i, client_secret_env: \"{var}\" }}\n"
        );
        for bad in [user, idp] {
            let err = parse(&bad).unwrap_err().to_string();
            assert!(err.contains(ENV_PREFIX), "{bad}: {err}");
        }
    }
    parse(
        "tenant: t\nusers:\n  - { email: a@b.c, display_name: A, password_env: OAUTH_APPLY_A_1 }\n",
    )
    .unwrap();
}

/// The prefix only protects the server's secrets while no variable the
/// server reads carries it.
#[test]
fn no_server_variable_uses_the_apply_prefix() {
    for source in [
        include_str!("../config/mod.rs"),
        include_str!("../config/env.rs"),
        include_str!("../config/smtp.rs"),
        include_str!("../config/telegram.rs"),
        include_str!("../config/public_url.rs"),
        include_str!("../../../../.env.example"),
    ] {
        assert!(!source.contains(ENV_PREFIX));
    }
}

#[test]
fn must_change_password_needs_a_password() {
    let bad =
        "tenant: t\nusers:\n  - { email: a@b.c, display_name: A, must_change_password: false }\n";
    let err = parse(bad).unwrap_err().to_string();
    assert!(err.contains("needs `password_env`"), "{err}");
}
