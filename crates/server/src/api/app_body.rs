//! The create / update body of `/api/v1/applications` and its validation.

use entity::{
    applications,
    enums::{AccessTokenFormat, AppMfaPolicy, ClientType, GroupsClaimFormat, SigningAlg},
};
use sea_orm::ActiveEnum;
use serde::{Deserialize, Deserializer};

use super::{
    app_rules::{ACCESS_TTL, refresh_ttl},
    set_changed, validate,
};
use crate::{
    directory::display_name,
    error::{AppError, AppResult},
};

/// `Some(None)` = explicit `null` (clear), `None` = absent (keep).
pub(super) fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

/// Create and update body. `client_id` / `client_type` are create-only.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppBody {
    pub client_id: Option<String>,
    pub client_type: Option<String>,
    pub display_name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    post_logout_redirect_uris: Option<Vec<String>>,
    web_origins: Option<Vec<String>>,
    #[serde(default, deserialize_with = "nullable")]
    identifier_uri: Option<Option<String>>,
    access_token_format: Option<String>,
    signing_alg: Option<String>,
    groups_claim_format: Option<String>,
    assignment_required: Option<bool>,
    access_token_ttl_secs: Option<i32>,
    refresh_token_ttl_secs: Option<i32>,
    device_code_enabled: Option<bool>,
    mfa_policy: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    backchannel_logout_uri: Option<Option<String>>,
    backchannel_logout_session_required: Option<bool>,
}

pub(super) fn parse<E: ActiveEnum<Value = String>>(
    raw: &str,
    field: &str,
    allowed: &str,
) -> AppResult<E> {
    E::try_from_value(&raw.to_owned())
        .map_err(|_| AppError::BadRequest(format!("{field} must be one of: {allowed}")))
}

/// Validates the settable fields and applies those whose value differs from
/// `row`; returns the changed names (unchanged values sent back are ignored,
/// so built-in / privileged-app rules only see real changes).
/// `allow_http_loopback` admits plain-http loopback back-channel URIs.
pub(super) fn apply(
    row: &mut applications::ActiveModel,
    body: &AppBody,
    client_id: &str,
    client_type: ClientType,
    allow_http_loopback: bool,
) -> AppResult<Vec<&'static str>> {
    let mut fields = Vec::new();
    let mut mark = |changed: bool, name: &'static str| {
        if changed {
            fields.push(name);
        }
    };
    if let Some(name) = &body.display_name {
        let name = display_name(name, "application")?;
        mark(set_changed(&mut row.display_name, name), "display_name");
    }
    if let Some(uris) = &body.redirect_uris {
        validate::redirect_uris(uris, "redirect_uris")?;
        mark(
            set_changed(&mut row.redirect_uris, uris.clone()),
            "redirect_uris",
        );
    }
    if let Some(uris) = &body.post_logout_redirect_uris {
        validate::redirect_uris(uris, "post_logout_redirect_uris")?;
        mark(
            set_changed(&mut row.post_logout_redirect_uris, uris.clone()),
            "post_logout_redirect_uris",
        );
    }
    if let Some(origins) = &body.web_origins {
        validate::web_origins(origins)?;
        mark(
            set_changed(&mut row.web_origins, origins.clone()),
            "web_origins",
        );
    }
    if let Some(uri) = &body.identifier_uri {
        if let Some(uri) = uri {
            validate::identifier_uri(uri, client_id)?;
        }
        mark(
            set_changed(&mut row.identifier_uri, uri.clone()),
            "identifier_uri",
        );
    }
    if let Some(raw) = &body.access_token_format {
        let format: AccessTokenFormat = parse(raw, "access_token_format", "jwt, opaque")?;
        mark(
            set_changed(&mut row.access_token_format, format),
            "access_token_format",
        );
    }
    if let Some(raw) = &body.signing_alg {
        let alg: SigningAlg = parse(raw, "signing_alg", "RS256, ES256")?;
        mark(set_changed(&mut row.signing_alg, alg), "signing_alg");
    }
    if let Some(raw) = &body.groups_claim_format {
        let format: GroupsClaimFormat = parse(raw, "groups_claim_format", "id, name")?;
        mark(
            set_changed(&mut row.groups_claim_format, format),
            "groups_claim_format",
        );
    }
    if let Some(required) = body.assignment_required {
        mark(
            set_changed(&mut row.assignment_required, required),
            "assignment_required",
        );
    }
    if let Some(ttl) = body.access_token_ttl_secs {
        if !ACCESS_TTL.contains(&ttl) {
            return Err(AppError::BadRequest(
                "access_token_ttl_secs must be 300-86400".into(),
            ));
        }
        mark(
            set_changed(&mut row.access_token_ttl_secs, ttl),
            "access_token_ttl_secs",
        );
    }
    if let Some(ttl) = body.refresh_token_ttl_secs {
        refresh_ttl(client_type, ttl)?;
        mark(
            set_changed(&mut row.refresh_token_ttl_secs, ttl),
            "refresh_token_ttl_secs",
        );
    }
    if let Some(enabled) = body.device_code_enabled {
        mark(
            set_changed(&mut row.device_code_enabled, enabled),
            "device_code_enabled",
        );
    }
    // An app can only tighten the tenant's policy, so `optional` isn't one.
    if let Some(raw) = &body.mfa_policy {
        let policy: AppMfaPolicy = parse(raw, "mfa_policy", "inherit, required")?;
        mark(set_changed(&mut row.mfa_policy, policy), "mfa_policy");
    }
    if let Some(uri) = &body.backchannel_logout_uri {
        if let Some(uri) = uri {
            validate::backchannel_logout_uri(uri, allow_http_loopback)?;
        }
        mark(
            set_changed(&mut row.backchannel_logout_uri, uri.clone()),
            "backchannel_logout_uri",
        );
    }
    if let Some(required) = body.backchannel_logout_session_required {
        mark(
            set_changed(&mut row.backchannel_logout_session_required, required),
            "backchannel_logout_session_required",
        );
    }
    Ok(fields)
}
