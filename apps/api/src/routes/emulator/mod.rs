pub mod idp_oidc;
pub mod idp_saml;
pub mod snapshot;

use axum::{
    extract::{Path, State},
    Json,
};
use serde_json::{json, Value};

use crate::{error::EmulatorError, seed, state::EmulatorState};

pub async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

pub async fn reset(State(state): State<EmulatorState>) -> Json<Value> {
    state.reset_stores().await;

    // Re-apply seed if configured
    if let Some(seed_path) = &state.config.seed_file.clone() {
        // Best-effort — log errors but don't fail the reset
        if let Err(e) = seed::load(seed_path, &state).await {
            tracing::warn!(error = %e, "Seed re-apply failed during reset");
        }
    }

    Json(json!({ "ok": true }))
}

/// GET /emulator/otp/:loginId
/// Returns the last-issued OTP code for the given login ID without consuming it.
/// This is an emulator-specific escape hatch for SDK-driven test flows.
pub async fn get_otp(
    State(state): State<EmulatorState>,
    Path(login_id): Path<String>,
) -> Result<Json<Value>, EmulatorError> {
    let user_id = {
        let users = state.users.read().await;
        let user = users.load(&login_id)?;
        user.user_id.clone()
    };

    let otps = state.otps.read().await;
    let code = otps.peek(&user_id).ok_or(EmulatorError::InvalidToken)?;
    Ok(Json(json!({ "code": code })))
}

/// POST /emulator/tenant
/// Creates a SAML tenant in the emulator's tenant store for testing.
/// Body: { "id": "...", "name": "...", "domains": ["example.com"], "authType": "saml" }
pub async fn create_tenant(
    State(state): State<EmulatorState>,
    Json(body): Json<serde_json::Value>,
) -> Json<Value> {
    use crate::types::{AuthType, Tenant};
    let id = body["id"].as_str().unwrap_or("test-tenant").to_string();
    let name = body["name"].as_str().unwrap_or(&id).to_string();
    let domains: Vec<String> = body["domains"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let auth_type = match body["authType"].as_str().unwrap_or("saml") {
        "oidc" => AuthType::Oidc,
        _ => AuthType::Saml,
    };
    let tenant = Tenant {
        id: id.clone(),
        name,
        domains,
        auth_type,
        ..Default::default()
    };
    state.tenants.write().await.insert(tenant);
    Json(json!({ "ok": true, "id": id }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::EmulatorConfig, state::EmulatorState, store::user_store::new_user_id, types::User,
    };

    async fn make_state() -> EmulatorState {
        let config = EmulatorConfig::default();
        EmulatorState::new(&config).await.unwrap()
    }

    async fn insert_user(state: &EmulatorState, login_id: &str) -> String {
        let uid = new_user_id();
        let mut u = User::default();
        u.user_id = uid.clone();
        u.login_ids = vec![login_id.to_string()];
        u.email = Some(login_id.to_string());
        u.status = "enabled".into();
        state.users.write().await.insert(u).unwrap();
        uid
    }

    #[tokio::test]
    async fn get_otp_returns_pending_code_without_consuming() {
        let state = make_state().await;
        let uid = insert_user(&state, "test@example.com").await;
        state.otps.write().await.store(&uid, "987654".into());

        let result = get_otp(State(state.clone()), Path("test@example.com".into()))
            .await
            .unwrap();
        assert_eq!(result["code"].as_str().unwrap(), "987654");
        // Code should still be present after peek
        assert!(state.otps.read().await.peek(&uid).is_some());
    }

    #[tokio::test]
    async fn get_otp_unknown_login_id_returns_user_not_found() {
        let state = make_state().await;
        let err = get_otp(State(state), Path("ghost@test.com".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, EmulatorError::UserNotFound));
    }

    #[tokio::test]
    async fn get_otp_no_pending_code_returns_invalid_token() {
        let state = make_state().await;
        insert_user(&state, "no-code@test.com").await;
        let err = get_otp(State(state), Path("no-code@test.com".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, EmulatorError::InvalidToken));
    }
}
