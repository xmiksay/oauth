// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `APEX_TENANT`: URLs the server hands out for the apex tenant (device
//! verification, federation callback) are on the apex origin.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    PUBLIC_URL,
    federation::{Fed, IDPS},
    flow::{Fixture, T},
    mgmt::call,
};
use serde_json::json;

async fn apex_fixture() -> Fixture {
    Fixture::with_env(&[("APEX_TENANT", T)], false).await
}

fn apex(path: &str) -> String {
    format!("{PUBLIC_URL}{path}")
}

#[tokio::test]
async fn device_verification_uri_is_on_the_apex() {
    let f = apex_fixture().await;
    common::device::enable(&f, &f.spa).await;
    let form = [("scope", "openid"), ("client_id", f.spa.client_id.as_str())];
    let (status, _, start) = f.post_form(&apex("/oauth2/devicecode"), &form, None).await;
    assert_eq!(status, StatusCode::OK, "{start}");
    assert_eq!(start["verification_uri"], apex("/device"));
    let code = start["user_code"].as_str().unwrap();
    assert_eq!(
        start["verification_uri_complete"],
        apex(&format!("/device?user_code={code}"))
    );
}

#[tokio::test]
async fn federation_callback_is_on_the_apex() {
    let fed = Fed::with(apex_fixture().await).await;
    let (status, created) = call(
        &fed.f.app,
        Method::POST,
        &apex(IDPS),
        Some(&fed.admin),
        Some(&fed.body(json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["redirect_uri"], apex("/federation/callback"));
}
