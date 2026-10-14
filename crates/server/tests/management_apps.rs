// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! App registrations through the management API, end to end with the
//! token endpoint.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    browser::{authorize_url, query_of},
    flow::{Fixture, WEB_CB},
    mgmt::{app_admin_token as admin, app_by_client_id, call, post},
};
use entity::audit_events;
use sea_orm::EntityTrait;
use serde_json::{Value, json};

const APPS: &str = "/api/v1/applications";
const CONSENTS: &str = "/api/v1/consents";

#[tokio::test]
async fn app_lifecycle_through_consent_and_tokens() {
    let f = Fixture::new().await;
    let token = admin(&f).await;

    // Resource: identifier URI, a delegated scope (admin consent) and an
    // application role.
    let (st, api) = post(
        &f,
        &token,
        APPS,
        json!({ "client_id": "billing", "display_name": "Billing API", "identifier_uri": "api://billing" }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{api}");
    assert_eq!(api["audience"], "api://billing");
    let api_path = format!("{APPS}/{}", api["id"].as_str().unwrap());
    let (st, scope) = post(
        &f,
        &token,
        &format!("{api_path}/scopes"),
        json!({ "value": "Billing.Read", "description": "Read invoices", "admin_consent_required": true }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{scope}");
    let (st, _) = post(
        &f,
        &token,
        &format!("{api_path}/roles"),
        json!({ "value": "Billing.Export", "display_name": "Export", "allowed_member_types": ["application"] }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    // Client: redirect URI, a secret and two required permissions.
    let (st, client) = post(
        &f,
        &token,
        APPS,
        json!({ "client_id": "billing-web", "display_name": "Billing Web", "redirect_uris": [WEB_CB] }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{client}");
    let client_path = format!("{APPS}/{}", client["id"].as_str().unwrap());
    let (st, secret) = post(
        &f,
        &token,
        &format!("{client_path}/secrets"),
        json!({ "description": "ci" }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{secret}");
    let secret_value = secret["secret"].as_str().unwrap().to_owned();
    assert_eq!(secret["hint"], secret_value[..3]);
    let (_, listed) = call(
        &f.app,
        Method::GET,
        &format!("{client_path}/secrets"),
        Some(&token),
        None,
    )
    .await;
    assert!(listed["items"][0].get("secret").is_none(), "{listed}");
    for (kind, value) in [
        ("delegated", "Billing.Read"),
        ("application", "Billing.Export"),
    ] {
        let body = json!({ "resource_application_id": api["id"], "type": kind, "value": value });
        let (st, body) = post(
            &f,
            &token,
            &format!("{client_path}/required-permissions"),
            body,
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "{body}");
    }
    let undeclared =
        json!({ "resource_application_id": api["id"], "type": "delegated", "value": "Nope" });
    let (st, _) = post(
        &f,
        &token,
        &format!("{client_path}/required-permissions"),
        undeclared,
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Before consent: client credentials get no roles; users are refused.
    let creds = [
        ("grant_type", "client_credentials"),
        ("scope", "api://billing/.default"),
    ];
    let basic = Some(("billing-web", secret_value.as_str()));
    let (st, _, body) = f.post_form("/oauth2/token", &creds, basic).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let claims = f
        .verify_jwt(body["access_token"].as_str().unwrap(), "api://billing")
        .await;
    assert!(claims.get("roles").is_none(), "{claims:?}");
    let url = authorize_url(
        "billing-web",
        WEB_CB,
        "openid offline_access api://billing/Billing.Read",
        &[],
    );
    let mut browser = f.browser();
    let tx = browser.authorize(&url).await.unwrap();
    let redirect = browser.complete_login(&tx, "ann@example.com").await;
    assert_eq!(query_of(&redirect)["error"], "access_denied", "{redirect}");

    // A scope that isn't required can't be granted; the full grant works.
    let body = json!({ "client_application_id": client["id"], "resource_application_id": api["id"], "scopes": ["Billing.Write"] });
    assert_eq!(
        post(&f, &token, CONSENTS, body).await.0,
        StatusCode::BAD_REQUEST
    );
    let body =
        json!({ "client_application_id": client["id"], "resource_application_id": api["id"] });
    let (st, granted) = post(&f, &token, CONSENTS, body).await;
    assert_eq!(st, StatusCode::OK, "{granted}");
    assert_eq!(granted["grant"]["scopes"], json!(["Billing.Read"]));
    assert_eq!(granted["grant"]["user_id"], Value::Null);
    assert_eq!(granted["role_assignments"].as_array().unwrap().len(), 1);

    // Client credentials now carry the role; the user flow passes.
    let (_, _, body) = f.post_form("/oauth2/token", &creds, basic).await;
    let claims = f
        .verify_jwt(body["access_token"].as_str().unwrap(), "api://billing")
        .await;
    assert_eq!(claims["roles"], json!(["Billing.Export"]));
    let client_model = app_by_client_id(&f.db, f.tenant.id, "billing-web").await;
    let code = browser.login_for_code(&url, "ann@example.com").await;
    let (st, tokens) = f
        .redeem(&client_model, Some(&secret_value), &code, WEB_CB)
        .await;
    assert_eq!(st, StatusCode::OK, "{tokens}");
    let claims = f
        .verify_jwt(tokens["access_token"].as_str().unwrap(), "api://billing")
        .await;
    assert_eq!(claims["scp"], "Billing.Read");
    let refresh = tokens["refresh_token"].as_str().unwrap();

    // Revoking the admin grant revokes the refresh tokens issued under it.
    let grant_path = format!("{CONSENTS}/{}", granted["grant"]["id"].as_str().unwrap());
    let (st, _) = call(&f.app, Method::DELETE, &grant_path, Some(&token), None).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let form = [("grant_type", "refresh_token"), ("refresh_token", refresh)];
    let (st, _, body) = f.post_form("/oauth2/token", &form, basic).await;
    assert_eq!(
        (st, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );

    // Every mutation was audited, and no secret value reached the log.
    let events = audit_events::Entity::find().all(&f.db).await.unwrap();
    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    for expected in [
        "application.create",
        "application.scope_add",
        "application.role_add",
        "application.secret_add",
        "application.permission_add",
        "consent.grant",
        "consent.revoke",
        "sign_in",
    ] {
        assert!(types.contains(&expected), "{expected} missing in {types:?}");
    }
    let log =
        serde_json::to_string(&events.iter().map(|e| &e.details).collect::<Vec<_>>()).unwrap();
    assert!(
        !log.contains(&secret_value) && !log.contains(common::flow::PASSWORD),
        "{log}"
    );
    assert!(!log.contains(refresh));

    // Deleting the client removes its secrets with it.
    let (st, _) = call(&f.app, Method::DELETE, &client_path, Some(&token), None).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, _, _) = f.post_form("/oauth2/token", &creds, basic).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}
