// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! App registration rules: built-in protection, input validation, token
//! lifetime caps and credential protection of privileged apps.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{
        app_admin_token as admin, app_by_client_id, call, mint_user_token, post, user_with_roles,
    },
};
use entity::enums::DirectoryRole::GlobalAdmin;
use serde_json::{Value, json};

const APPS: &str = "/api/v1/applications";

#[tokio::test]
async fn builtin_apps_are_protected() {
    let f = Fixture::new().await;
    let token = admin(&f).await;
    let api = app_by_client_id(&f.db, f.tenant.id, "management-api").await;
    let portal = app_by_client_id(&f.db, f.tenant.id, "admin-portal").await;
    let api_path = format!("{APPS}/{}", api.id);
    let portal_path = format!("{APPS}/{}", portal.id);

    let (st, _) = call(&f.app, Method::DELETE, &api_path, Some(&token), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let edit = json!({ "redirect_uris": ["https://evil.example/cb"] });
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        &portal_path,
        Some(&token),
        Some(&edit),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let edit = json!({ "identifier_uri": "https://evil.example" });
    let (st, _) = call(&f.app, Method::PATCH, &api_path, Some(&token), Some(&edit)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    for sub in ["scopes", "secrets"] {
        let body = json!({ "value": "X.Y" });
        let (st, _) = post(
            &f,
            &token,
            &format!("{api_path}/{sub}"),
            if sub == "secrets" { json!({}) } else { body },
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{sub}");
    }
    // Display name and token lifetimes stay editable — by a GlobalAdmin
    // only, and within the lifetime caps (public SPA: one week).
    let edit = json!({ "display_name": "Contoso Admin", "access_token_ttl_secs": 900 });
    let patch = |token: String, body: Value| {
        let (app, path) = (f.app.clone(), portal_path.clone());
        async move { call(&app, Method::PATCH, &path, Some(&token), Some(&body)).await }
    };
    assert_eq!(
        patch(token.clone(), edit.clone()).await.0,
        StatusCode::FORBIDDEN
    );
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let ga = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let (st, body) = patch(ga.clone(), edit).await;
    assert_eq!(
        (st, body["display_name"].as_str()),
        (StatusCode::OK, Some("Contoso Admin"))
    );
    for ttl in [i32::MAX, 7 * 86_400 + 1, 0] {
        let (st, _) = patch(ga.clone(), json!({ "refresh_token_ttl_secs": ttl })).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{ttl}");
    }
    assert_eq!(
        patch(ga, json!({ "refresh_token_ttl_secs": 7 * 86_400 }))
            .await
            .0,
        StatusCode::OK
    );
    // Confidential apps: 90 days at most; new public clients default to 24 h.
    let too_long = json!({ "display_name": "C", "refresh_token_ttl_secs": 90 * 86_400 + 1 });
    assert_eq!(
        post(&f, &token, APPS, too_long).await.0,
        StatusCode::BAD_REQUEST
    );
    let (st, spa) = post(
        &f,
        &token,
        APPS,
        json!({ "display_name": "S", "client_type": "public" }),
    )
    .await;
    assert_eq!(
        (st, spa["refresh_token_ttl_secs"].as_i64()),
        (StatusCode::CREATED, Some(86_400))
    );
}

#[tokio::test]
async fn credentials_of_privileged_apps_need_a_global_admin() {
    let f = Fixture::new().await;
    let aa = admin(&f).await;
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let ga = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let (_, svc) = post(
        &f,
        &aa,
        APPS,
        json!({ "client_id": "svc", "display_name": "Svc" }),
    )
    .await;
    let svc_path = format!("{APPS}/{}", svc["id"].as_str().unwrap());
    let (st, first) = post(&f, &aa, &format!("{svc_path}/secrets"), json!({})).await;
    assert_eq!(
        st,
        StatusCode::CREATED,
        "ordinary app: ApplicationAdmin may"
    );

    // A GlobalAdmin grants it Directory.ReadWrite.All…
    let api = app_by_client_id(&f.db, f.tenant.id, "management-api").await;
    let (_, roles) = call(
        &f.app,
        Method::GET,
        &format!("{APPS}/{}/roles", api.id),
        Some(&ga),
        None,
    )
    .await;
    let rw = roles["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["value"] == "Directory.ReadWrite.All")
        .unwrap()["id"]
        .clone();
    let assign =
        json!({ "app_role_id": rw, "principal_type": "application", "principal_id": svc["id"] });
    let (st, _) = post(&f, &ga, "/api/v1/role-assignments", assign).await;
    assert_eq!(st, StatusCode::CREATED);

    // …so its credentials and redirect URIs are now GlobalAdmin-only.
    let (st, _) = post(&f, &aa, &format!("{svc_path}/secrets"), json!({})).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let one = format!("{svc_path}/secrets/{}", first["id"].as_str().unwrap());
    assert_eq!(
        call(&f.app, Method::DELETE, &one, Some(&aa), None).await.0,
        StatusCode::FORBIDDEN
    );
    let uris = json!({ "redirect_uris": ["https://attacker.example/cb"] });
    let (st, _) = call(&f.app, Method::PATCH, &svc_path, Some(&aa), Some(&uris)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let rename = json!({ "display_name": "Service" });
    let (st, _) = call(&f.app, Method::PATCH, &svc_path, Some(&aa), Some(&rename)).await;
    assert_eq!(st, StatusCode::OK, "non-credential fields stay editable");
    let (st, _) = post(&f, &ga, &format!("{svc_path}/secrets"), json!({})).await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(
        call(&f.app, Method::DELETE, &one, Some(&ga), None).await.0,
        StatusCode::NO_CONTENT
    );

    // Per-app caps: at most 50 secrets.
    for _ in 0..49 {
        assert_eq!(
            post(&f, &ga, &format!("{svc_path}/secrets"), json!({}))
                .await
                .0,
            StatusCode::CREATED
        );
    }
    assert_eq!(
        post(&f, &ga, &format!("{svc_path}/secrets"), json!({}))
            .await
            .0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn registration_input_is_validated() {
    let f = Fixture::new().await;
    let token = admin(&f).await;
    let create = |body: Value| post(&f, &token, APPS, body);

    // identifier_uri: `api://` only for the own client_id, lowercase scheme.
    for uri in ["api://someone-else", "API://x1", "Api://x1", "api://x1/"] {
        let (st, body) =
            create(json!({ "client_id": "x1", "display_name": "X", "identifier_uri": uri })).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{uri}: {body}");
    }
    let (st, x1) =
        create(json!({ "client_id": "x1", "display_name": "X", "identifier_uri": "api://x1" }))
            .await;
    assert_eq!(st, StatusCode::CREATED, "{x1}");
    let (st, _) = create(json!({ "client_id": "x1", "display_name": "dup" })).await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, _) =
        create(json!({ "display_name": "Y", "identifier_uri": "https://api.contoso.com/y" })).await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, _) =
        create(json!({ "display_name": "Z", "identifier_uri": "https://api.contoso.com/y" })).await;
    assert_eq!(st, StatusCode::CONFLICT);

    // Redirect URIs: https, or http only to an IP loopback; no fragments.
    for uri in [
        "http://app.example/cb",
        "https://app.example/cb#x",
        "http://localhost/cb",
        "ftp://x/y",
    ] {
        let (st, _) = create(json!({ "display_name": "R", "redirect_uris": [uri] })).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{uri}");
    }
    let (st, _) = create(
        json!({ "display_name": "R", "post_logout_redirect_uris": ["http://evil.example/"] }),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = create(json!({ "display_name": "R", "redirect_uris": ["http://127.0.0.1/cb", "https://ok.example/cb"] })).await;
    assert_eq!(st, StatusCode::CREATED);

    // Token configuration within the schema's bounds.
    for bad in [
        json!({ "display_name": "T", "access_token_ttl_secs": 60 }),
        json!({ "display_name": "T", "access_token_ttl_secs": 86_401 }),
        json!({ "display_name": "T", "refresh_token_ttl_secs": 0 }),
        json!({ "display_name": "T", "access_token_format": "saml" }),
        json!({ "display_name": "T", "signing_alg": "HS256" }),
        json!({ "display_name": "T", "unknown_field": 1 }),
    ] {
        assert_eq!(
            create(bad.clone()).await.0,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    let (st, app) = create(json!({ "display_name": "T", "access_token_format": "opaque", "signing_alg": "ES256", "access_token_ttl_secs": 600 })).await;
    assert_eq!(
        (
            st,
            app["access_token_format"].as_str(),
            app["signing_alg"].as_str()
        ),
        (StatusCode::CREATED, Some("opaque"), Some("ES256"))
    );

    // Reserved scope values (any case) and bad characters are rejected.
    let scopes = format!("{APPS}/{}/scopes", x1["id"].as_str().unwrap());
    for value in [
        "openid",
        "OpenID",
        "profile",
        "email",
        "offline_access",
        ".default",
        "a b",
        "a/b",
    ] {
        let (st, _) = post(&f, &token, &scopes, json!({ "value": value })).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{value}");
    }
    let (st, _) = post(&f, &token, &scopes, json!({ "value": "X.Read" })).await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, _) = post(&f, &token, &scopes, json!({ "value": "X.Read" })).await;
    assert_eq!(st, StatusCode::CONFLICT);

    // Roles: allowed member types are enforced on assignment.
    let roles = format!("{APPS}/{}/roles", x1["id"].as_str().unwrap());
    let (st, role) = post(
        &f,
        &token,
        &roles,
        json!({ "value": "X.Admin", "display_name": "Admin", "allowed_member_types": ["user"] }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{role}");
    let assign = "/api/v1/role-assignments";
    let to_app = json!({ "app_role_id": role["id"], "principal_type": "application", "principal_id": f.web.id });
    assert_eq!(
        post(&f, &token, assign, to_app).await.0,
        StatusCode::BAD_REQUEST
    );
    let to_group =
        json!({ "app_role_id": role["id"], "principal_type": "group", "principal_id": f.group });
    assert_eq!(
        post(&f, &token, assign, to_group.clone()).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        post(&f, &token, assign, to_group).await.0,
        StatusCode::CONFLICT
    );
    let ghost = json!({ "app_role_id": role["id"], "principal_type": "user", "principal_id": uuid::Uuid::now_v7() });
    assert_eq!(
        post(&f, &token, assign, ghost).await.0,
        StatusCode::BAD_REQUEST
    );
}
