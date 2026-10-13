// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! PATCH applies (and audits, and runs change-only rules on) only values that
//! actually change: clients may send back unchanged fields.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{
        app_admin_token, app_by_client_id, audited, call, mint_user_token, post, user_with_roles,
    },
};
use entity::enums::DirectoryRole::GlobalAdmin;
use oauth_server::{bootstrap, directory};
use serde_json::json;
use uuid::Uuid;

const APPS: &str = "/api/v1/tenants/contoso/applications";

async fn global_admin(f: &Fixture) -> String {
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    mint_user_token(&f.db, &f.config, &f.tenant, &ga).await
}

#[tokio::test]
async fn builtin_app_accepts_unchanged_non_editable_fields() {
    let f = Fixture::new().await;
    let ga = global_admin(&f).await;
    let portal = app_by_client_id(&f.db, f.tenant.id, "admin-portal").await;
    let path = format!("{APPS}/{}", portal.id);

    // Echoing the current signing_alg / format / redirect URIs is no change.
    let echo = json!({
        "signing_alg": "RS256",
        "access_token_format": "jwt",
        "redirect_uris": portal.redirect_uris,
    });
    let (st, body) = call(&f.app, Method::PATCH, &path, Some(&ga), Some(&echo)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(
        audited(&f.db, "application.update", portal.id)
            .await
            .is_empty()
    );

    // A real change to a non-editable field is still refused…
    let alg = json!({ "signing_alg": "ES256" });
    let (st, _) = call(&f.app, Method::PATCH, &path, Some(&ga), Some(&alg)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    // …and an editable change sent along with echoed fields lists only itself.
    let rename = json!({ "display_name": "Portal", "signing_alg": "RS256" });
    let (st, _) = call(&f.app, Method::PATCH, &path, Some(&ga), Some(&rename)).await;
    assert_eq!(st, StatusCode::OK);
    let events = audited(&f.db, "application.update", portal.id).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["fields"], json!(["display_name"]));
}

#[tokio::test]
async fn application_admin_renames_privileged_app_resending_its_redirect_uris() {
    let f = Fixture::new().await;
    let aa = app_admin_token(&f).await;
    let ga = global_admin(&f).await;
    let create = json!({
        "client_id": "svc",
        "display_name": "Svc",
        "redirect_uris": ["https://svc.example/cb"],
    });
    let (_, svc) = post(&f, &aa, APPS, create).await;
    let svc_id: Uuid = svc["id"].as_str().unwrap().parse().unwrap();
    let svc_path = format!("{APPS}/{svc_id}");

    // Make it privileged: a management-API app role assignment.
    let api = app_by_client_id(&f.db, f.tenant.id, "management-api").await;
    let roles_path = format!("{APPS}/{}/roles", api.id);
    let (_, roles) = call(&f.app, Method::GET, &roles_path, Some(&ga), None).await;
    let rw = roles["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["value"] == "Directory.ReadWrite.All")
        .unwrap()["id"]
        .clone();
    let assign =
        json!({ "app_role_id": rw, "principal_type": "application", "principal_id": svc_id });
    let (st, _) = post(&f, &ga, "/api/v1/tenants/contoso/role-assignments", assign).await;
    assert_eq!(st, StatusCode::CREATED);

    let edit = json!({
        "display_name": "Service",
        "redirect_uris": ["https://svc.example/cb"],
        "post_logout_redirect_uris": [],
    });
    let (st, body) = call(&f.app, Method::PATCH, &svc_path, Some(&aa), Some(&edit)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let events = audited(&f.db, "application.update", svc_id).await;
    assert_eq!(events.last().unwrap()["fields"], json!(["display_name"]));

    let steal = json!({ "redirect_uris": ["https://attacker.example/cb"] });
    let (st, _) = call(&f.app, Method::PATCH, &svc_path, Some(&aa), Some(&steal)).await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "real credential changes stay GA-only"
    );
}

#[tokio::test]
async fn unchanged_tenant_values_are_not_audited() {
    let f = Fixture::new().await;
    let opts = bootstrap::Options {
        admin_email: "root@example.com".into(),
        display_name: None,
        reset_password: false,
    };
    bootstrap::run(&f.db, &f.config, &opts).await.unwrap();
    let system = directory::find_system_tenant(&f.db).await.unwrap().unwrap();
    let root = directory::find_user_by_email(&f.db, system.id, "root@example.com")
        .await
        .unwrap()
        .unwrap();
    let root = mint_user_token(&f.db, &f.config, &system, &root).await;

    let echo = json!({
        "disabled": false,
        "display_name": f.tenant.display_name,
        "audit_retention_days": f.tenant.audit_retention_days,
    });
    let path = "/api/v1/tenants/contoso";
    let (st, body) = call(&f.app, Method::PATCH, path, Some(&root), Some(&echo)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(
        audited(&f.db, "tenant.update", f.tenant.id)
            .await
            .is_empty()
    );

    // The tenant's own GlobalAdmin echoing its settings: no event either.
    let ga = global_admin(&f).await;
    let settings = json!({ "display_name": f.tenant.display_name });
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        "/api/v1/tenants/contoso/settings",
        Some(&ga),
        Some(&settings),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        audited(&f.db, "tenant.update", f.tenant.id)
            .await
            .is_empty()
    );

    let rename = json!({ "display_name": "Contoso Ltd", "disabled": false });
    let (st, _) = call(&f.app, Method::PATCH, path, Some(&root), Some(&rename)).await;
    assert_eq!(st, StatusCode::OK);
    let events = audited(&f.db, "tenant.update", f.tenant.id).await;
    assert!(!events.is_empty());
    assert!(
        events
            .iter()
            .all(|e| e["fields"] == json!(["display_name"]))
    );
}
