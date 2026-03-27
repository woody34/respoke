use crate::extractor::PermissiveJson;
use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    auth_policy::AuthPolicyGuard,
    connector::invoker::password_reset_payload,
    cookies::build_auth_cookies,
    error::EmulatorError,
    jwt::token_generator::{generate_refresh_jwt, generate_session_jwt},
    state::EmulatorState,
    store::token_store::generate_token,
    store::user_store::new_user_id,
    types::{TokenType, User},
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn masked_email(email: &str) -> String {
    if let Some((user, domain)) = email.split_once('@') {
        let masked = if user.len() <= 2 {
            "*".repeat(user.len())
        } else {
            format!("{}***", &user[..2])
        };
        format!("{masked}@{domain}")
    } else {
        "***".into()
    }
}

fn build_jwt_response(
    state: &EmulatorState,
    _user_id: &str,
    session_jwt: &str,
    refresh_jwt: &str,
    user_resp: serde_json::Value,
) -> Value {
    let exp = now() + state.config.session_ttl;
    json!({
        "sessionJwt": session_jwt,
        "refreshJwt": refresh_jwt,
        "cookieDomain": "",
        "cookiePath": "/",
        "cookieMaxAge": state.config.session_ttl,
        "cookieExpiration": exp,
        "firstSeen": false,
        "user": user_resp
    })
}

// ─── Signup ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignupRequest {
    pub login_id: String,
    pub password: String,
    pub user: Option<UserFields>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserFields {
    pub email: Option<String>,
    pub phone: Option<String>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
}

pub async fn signup(
    State(state): State<EmulatorState>,
    PermissiveJson(req): PermissiveJson<SignupRequest>,
) -> Result<(axum::http::HeaderMap, Json<Value>), EmulatorError> {
    AuthPolicyGuard::check_method_enabled(&state, "password").await?;
    let fields = req.user.unwrap_or_default();
    let user_id = new_user_id();
    let email = fields.email.clone().or_else(|| {
        if req.login_id.contains('@') {
            Some(req.login_id.clone())
        } else {
            None
        }
    });

    let mut user = User {
        user_id: user_id.clone(),
        login_ids: vec![req.login_id.clone()],
        email,
        phone: fields.phone,
        name: fields.name,
        given_name: fields.given_name,
        family_name: fields.family_name,
        status: "enabled".into(),
        created_time: now(),
        password: true,
        ..Default::default()
    };

    let hash = tokio::task::spawn_blocking({
        let pwd = req.password.clone();
        move || bcrypt::hash(&pwd, 10).map_err(|e| EmulatorError::Internal(e.to_string()))
    })
    .await
    .map_err(|e| EmulatorError::Internal(e.to_string()))??;

    user._password_hash = Some(hash);

    {
        let mut users = state.users.write().await;
        users.insert(user)?;
    }

    let user_ref = state.users.read().await;
    let user = user_ref.load(&req.login_id)?;
    let tmpl_store = state.jwt_templates.read().await;
    let active_tmpl = tmpl_store.active();
    let session_jwt = generate_session_jwt(
        &*state.km().await,
        user,
        &state.config.project_id,
        state.config.session_ttl,
        active_tmpl,
        &*state.roles.read().await,
        "pwd",
    )
    .map_err(|e| EmulatorError::Internal(e.to_string()))?;
    let refresh_jwt = generate_refresh_jwt(
        &*state.km().await,
        &user.user_id,
        &state.config.project_id,
        state.config.refresh_ttl,
    )
    .map_err(|e| EmulatorError::Internal(e.to_string()))?;

    let user_resp = serde_json::to_value(user.to_response()).unwrap();
    let cookies = build_auth_cookies(&session_jwt, &refresh_jwt, state.config.session_ttl);
    let body = build_jwt_response(&state, &user.user_id, &session_jwt, &refresh_jwt, user_resp);
    drop(user_ref);

    // Record login timestamp
    let _ = state.users.write().await.record_login(&req.login_id);

    Ok((cookies, Json(body)))
}

// ─── Signin ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigninRequest {
    pub login_id: String,
    pub password: String,
}

pub async fn signin(
    State(state): State<EmulatorState>,
    PermissiveJson(req): PermissiveJson<SigninRequest>,
) -> Result<(axum::http::HeaderMap, Json<Value>), EmulatorError> {
    AuthPolicyGuard::check_method_enabled(&state, "password").await?;
    AuthPolicyGuard::check_not_locked_out(&state, &req.login_id).await?;

    // Verify password with spawn_blocking
    let valid = {
        let users = state.users.read().await;
        let hash = users
            .load(&req.login_id)?
            ._password_hash
            .clone()
            .ok_or(EmulatorError::InvalidCredentials)?;
        let pwd = req.password.clone();
        tokio::task::spawn_blocking(move || bcrypt::verify(&pwd, &hash))
            .await
            .map_err(|e| EmulatorError::Internal(e.to_string()))?
            .map_err(|_| EmulatorError::InvalidCredentials)?
    };
    if !valid {
        AuthPolicyGuard::record_failure(&state, &req.login_id).await;
        return Err(EmulatorError::InvalidCredentials);
    }
    AuthPolicyGuard::clear_failures(&state, &req.login_id).await;

    let users = state.users.read().await;
    let user = users.load(&req.login_id)?;
    if user.status == "disabled" {
        return Err(EmulatorError::UserDisabled);
    }
    let tmpl_store = state.jwt_templates.read().await;
    let active_tmpl = tmpl_store.active();
    let session_jwt = generate_session_jwt(
        &*state.km().await,
        user,
        &state.config.project_id,
        state.config.session_ttl,
        active_tmpl,
        &*state.roles.read().await,
        "pwd",
    )
    .map_err(|e| EmulatorError::Internal(e.to_string()))?;
    let refresh_jwt = generate_refresh_jwt(
        &*state.km().await,
        &user.user_id,
        &state.config.project_id,
        state.config.refresh_ttl,
    )
    .map_err(|e| EmulatorError::Internal(e.to_string()))?;

    let user_resp = serde_json::to_value(user.to_response()).unwrap();
    let cookies = build_auth_cookies(&session_jwt, &refresh_jwt, state.config.session_ttl);
    let body = build_jwt_response(&state, &user.user_id, &session_jwt, &refresh_jwt, user_resp);
    drop(users);

    // Record login timestamp
    let _ = state.users.write().await.record_login(&req.login_id);

    Ok((cookies, Json(body)))
}

// ─── Replace password ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplaceRequest {
    pub login_id: String,
    pub old_password: String,
    pub new_password: String,
}

pub async fn replace(
    State(state): State<EmulatorState>,
    PermissiveJson(req): PermissiveJson<ReplaceRequest>,
) -> Result<(axum::http::HeaderMap, Json<Value>), EmulatorError> {
    {
        let users = state.users.read().await;
        let hash = users
            .load(&req.login_id)?
            ._password_hash
            .clone()
            .ok_or(EmulatorError::InvalidCredentials)?;
        let old_pwd = req.old_password.clone();
        let valid = tokio::task::spawn_blocking(move || bcrypt::verify(&old_pwd, &hash))
            .await
            .map_err(|e| EmulatorError::Internal(e.to_string()))?
            .map_err(|_| EmulatorError::InvalidCredentials)?;
        if !valid {
            return Err(EmulatorError::InvalidCredentials);
        }
    }

    let new_hash = {
        let pwd = req.new_password.clone();
        tokio::task::spawn_blocking(move || {
            bcrypt::hash(&pwd, 10).map_err(|e| EmulatorError::Internal(e.to_string()))
        })
        .await
        .map_err(|e| EmulatorError::Internal(e.to_string()))??
    };
    state
        .users
        .write()
        .await
        .set_password(&req.login_id, new_hash)?;

    let users = state.users.read().await;
    let user = users.load(&req.login_id)?;
    let tmpl_store = state.jwt_templates.read().await;
    let active_tmpl = tmpl_store.active();
    let session_jwt = generate_session_jwt(
        &*state.km().await,
        user,
        &state.config.project_id,
        state.config.session_ttl,
        active_tmpl,
        &*state.roles.read().await,
        "pwd",
    )
    .map_err(|e| EmulatorError::Internal(e.to_string()))?;
    let refresh_jwt = generate_refresh_jwt(
        &*state.km().await,
        &user.user_id,
        &state.config.project_id,
        state.config.refresh_ttl,
    )
    .map_err(|e| EmulatorError::Internal(e.to_string()))?;
    let user_resp = serde_json::to_value(user.to_response()).unwrap();
    let cookies = build_auth_cookies(&session_jwt, &refresh_jwt, state.config.session_ttl);
    let body = build_jwt_response(&state, &user.user_id, &session_jwt, &refresh_jwt, user_resp);

    Ok((cookies, Json(body)))
}

// ─── Send reset ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendResetRequest {
    pub login_id: String,
}

pub async fn send_reset(
    State(state): State<EmulatorState>,
    PermissiveJson(req): PermissiveJson<SendResetRequest>,
) -> Result<Json<Value>, EmulatorError> {
    let users = state.users.read().await;
    let user = users.load(&req.login_id)?;
    let email = user.email.clone().unwrap_or_default();
    let masked = masked_email(&email);

    // Store a reset token so update_password can consume it
    let token = generate_token();
    let uid = user.user_id.clone();
    drop(users);
    state
        .tokens
        .write()
        .await
        .insert(token.clone(), uid, TokenType::Reset);

    // Fire-and-forget: notify reset connector (if configured)
    let reset_connector_id = state
        .auth_method_config
        .read()
        .await
        .get()
        .password
        .reset_connector_id
        .clone();
    if let Some(cid) = reset_connector_id {
        if let Ok(c) = state.connectors.read().await.load(&cid).cloned() {
            let inv = state.invoker.clone();
            let payload = password_reset_payload(&req.login_id, &token);
            tokio::spawn(async move { inv.invoke(&c, payload).await });
        }
    }

    Ok(Json(json!({
        "ok": true,
        "resetMethod": "email",
        "maskedEmail": masked,
        "token": token  // Emulator returns token for test convenience
    })))
}

// ─── Update password from reset token ─────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePasswordRequest {
    pub login_id: String,
    pub new_password: String,
    pub token: Option<String>,
}

pub async fn update_password(
    State(state): State<EmulatorState>,
    req: axum::extract::Request,
) -> Result<Json<Value>, EmulatorError> {
    // The SDK sends the reset token via "Authorization: Bearer projectId:token"
    // Raw HTTP clients send it in the body. Support both.
    let header_token = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            let bearer = s.strip_prefix("Bearer ")?;
            // Strip optional "projectId:" prefix
            let tok = bearer.find(':').map(|i| &bearer[i + 1..]).unwrap_or(bearer);
            if tok.is_empty() {
                None
            } else {
                Some(tok.to_string())
            }
        });

    let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .map_err(|e| EmulatorError::Internal(e.to_string()))?;
    let body: UpdatePasswordRequest = serde_json::from_slice(if body_bytes.is_empty() {
        b"{}"
    } else {
        &body_bytes
    })
    .map_err(|e| EmulatorError::Internal(e.to_string()))?;

    // Token is required — header takes priority, body is fallback
    let token = header_token
        .or(body.token)
        .ok_or(EmulatorError::Unauthorized)?;

    state.tokens.write().await.consume(&token)?;

    let new_hash = {
        let pwd = body.new_password.clone();
        tokio::task::spawn_blocking(move || {
            bcrypt::hash(&pwd, 10).map_err(|e| EmulatorError::Internal(e.to_string()))
        })
        .await
        .map_err(|e| EmulatorError::Internal(e.to_string()))??
    };
    state
        .users
        .write()
        .await
        .set_password(&body.login_id, new_hash)?;
    Ok(Json(json!({ "ok": true })))
}

// ─── Password policy (static) ─────────────────────────────────────────────────

/// GET /v1/auth/password/policy — returns a static permissive policy for emulator use.
pub async fn policy() -> Json<Value> {
    Json(json!({
        "active": true,
        "minLength": 6,
        "maxLength": 128,
        "lowercase": false,
        "uppercase": false,
        "number": false,
        "nonAlphanumeric": false
    }))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn policy_returns_expected_shape() {
        let result = policy().await;
        let body = result.0;
        assert_eq!(body["active"], true);
        assert_eq!(body["minLength"], 6);
        assert_eq!(body["maxLength"], 128);
        assert_eq!(body["lowercase"], false);
        assert_eq!(body["uppercase"], false);
        assert_eq!(body["number"], false);
        assert_eq!(body["nonAlphanumeric"], false);
    }
}
