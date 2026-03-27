use crate::extractor::PermissiveJson;
use axum::{
    extract::{Request, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    cookies::build_auth_cookies,
    error::EmulatorError,
    jwt::{
        token_generator::{generate_refresh_jwt, generate_session_jwt},
        token_validator::{validate_refresh_jwt, validate_session_jwt},
    },
    state::EmulatorState,
};

fn extract_refresh_jwt(req: &Request, body_token: Option<&str>) -> Option<String> {
    // Try Authorization header first.
    // @descope/core-js-sdk sends "Bearer projectId:jwtToken" — strip the prefix.
    if let Some(auth) = req.headers().get("Authorization") {
        if let Ok(s) = auth.to_str() {
            if let Some(bearer) = s.strip_prefix("Bearer ") {
                // Strip optional "projectId:" prefix
                let token = bearer.find(':').map(|i| &bearer[i + 1..]).unwrap_or(bearer);
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
    }
    // Try DSR cookie
    if let Some(cookie_header) = req.headers().get("cookie") {
        if let Ok(s) = cookie_header.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("DSR=") {
                    return Some(val.to_string());
                }
            }
        }
    }
    // Try body field
    body_token.map(|t| t.to_string())
}

// ─── Refresh ──────────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_jwt: Option<String>,
}

pub async fn refresh(
    State(state): State<EmulatorState>,
    req: Request,
) -> Result<(axum::http::HeaderMap, Json<Value>), EmulatorError> {
    // Extract DSR cookie and Authorization header BEFORE consuming the body
    let cookie_token = extract_refresh_jwt(&req, None);

    let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .map_err(|e| EmulatorError::Internal(e.to_string()))?;
    let body: RefreshRequest = serde_json::from_slice(&body_bytes).unwrap_or_default();

    // Priority: header/cookie > body field
    let token_str = cookie_token
        .or(body.refresh_jwt)
        .ok_or(EmulatorError::Unauthorized)?;

    // Check string-level revocation
    if state.revoked.read().await.is_revoked(&token_str) {
        return Err(EmulatorError::TokenExpired);
    }

    let claims = validate_refresh_jwt(&*state.km().await, &token_str)?;
    let user_id = claims.sub;

    // Check per-user logoutAll timestamp revocation
    {
        let revocations = state.user_revocations.read().await;
        if let Some(&revoked_at) = revocations.get(&user_id) {
            if claims.iat < revoked_at {
                return Err(EmulatorError::TokenExpired);
            }
        }
    }

    {
        let users = state.users.read().await;
        let user = users.load_by_user_id(&user_id)?;
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

        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + state.config.session_ttl;
        let user_resp = serde_json::to_value(user.to_response()).unwrap();
        let cookies = build_auth_cookies(&session_jwt, &refresh_jwt, state.config.session_ttl);
        let body = json!({
            "sessionJwt": session_jwt,
            "refreshJwt": refresh_jwt,
            "cookieDomain": "",
            "cookiePath": "/",
            "cookieMaxAge": state.config.session_ttl,
            "cookieExpiration": exp,
            "firstSeen": false,
            "user": user_resp
        });
        Ok((cookies, Json(body)))
    }
}

// ─── Logout ───────────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LogoutRequest {
    pub refresh_jwt: Option<String>,
}

pub async fn logout(
    State(state): State<EmulatorState>,
    req: Request,
) -> Result<Json<Value>, EmulatorError> {
    // Extract token from Authorization header BEFORE consuming the body
    let header_token = extract_refresh_jwt(&req, None);

    let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .map_err(|e| EmulatorError::Internal(e.to_string()))?;
    let body: LogoutRequest = serde_json::from_slice(&body_bytes).unwrap_or_default();

    // Header/cookie takes priority, body refreshJwt as fallback
    let token = header_token
        .or(body.refresh_jwt)
        .ok_or(EmulatorError::Unauthorized)?;

    // Validate it's a real JWT before revoking
    validate_refresh_jwt(&*state.km().await, &token)?;
    state.revoked.write().await.revoke(token);
    Ok(Json(json!({ "ok": true })))
}

// ─── Me ───────────────────────────────────────────────────────────────────────

pub async fn me(
    State(state): State<EmulatorState>,
    req: Request,
) -> Result<Json<Value>, EmulatorError> {
    let token_str = extract_refresh_jwt(&req, None).ok_or(EmulatorError::Unauthorized)?;

    if state.revoked.read().await.is_revoked(&token_str) {
        return Err(EmulatorError::TokenExpired);
    }

    // Real Descope /me accepts both session and refresh JWTs.
    // Try session JWT first (short-lived, typically what React SDK passes),
    // then fall back to refresh JWT (long-lived, typically what server SDKs use).
    let user_id = {
        let km = state.km().await;
        if let Ok(session_claims) = validate_session_jwt(&*km, &token_str) {
            session_claims.sub
        } else {
            let claims = validate_refresh_jwt(&*km, &token_str)?;

            // Check per-user logoutAll timestamp revocation
            {
                let revocations = state.user_revocations.read().await;
                if let Some(&revoked_at) = revocations.get(&claims.sub) {
                    if claims.iat < revoked_at {
                        return Err(EmulatorError::TokenExpired);
                    }
                }
            }

            claims.sub
        }
    };

    let users = state.users.read().await;
    let user = users.load_by_user_id(&user_id)?;
    Ok(Json(json!({ "user": user.to_response() })))
}

// ─── Validate session ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateRequest {
    pub session_jwt: String,
}

pub async fn validate(
    State(state): State<EmulatorState>,
    PermissiveJson(req): PermissiveJson<ValidateRequest>,
) -> Result<Json<Value>, EmulatorError> {
    let claims = validate_session_jwt(&*state.km().await, &req.session_jwt)?;

    // Check per-user force-logout revocation
    {
        let revocations = state.user_revocations.read().await;
        if let Some(&revoked_at) = revocations.get(&claims.sub) {
            if claims.iat < revoked_at {
                return Err(EmulatorError::TokenExpired);
            }
        }
    }

    let token_value =
        serde_json::to_value(&claims).map_err(|e| EmulatorError::Internal(e.to_string()))?;
    Ok(Json(json!({
        "jwt": req.session_jwt,
        "token": token_value,
        "cookies": []
    })))
}


// ─── Logout All ───────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LogoutAllRequest {
    pub refresh_jwt: Option<String>,
}

pub async fn logout_all(
    State(state): State<EmulatorState>,
    req: Request,
) -> Result<Json<Value>, EmulatorError> {
    let header_token = extract_refresh_jwt(&req, None);

    let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .map_err(|e| EmulatorError::Internal(e.to_string()))?;
    let body: LogoutAllRequest = serde_json::from_slice(&body_bytes).unwrap_or_default();

    let token = header_token
        .or(body.refresh_jwt)
        .ok_or(EmulatorError::Unauthorized)?;

    // Validate the token first — must be a real JWT
    let claims = validate_refresh_jwt(&*state.km().await, &token)?;
    let user_id = claims.sub;

    // Directly revoke this specific token string (handles same-second re-issue edge case).
    state.revoked.write().await.revoke(token);

    // Store iat as revocation boundary: any OTHER token for this user with
    // iat < claims.iat is also revoked (catches pre-existing sessions).
    // We use claims.iat so that tokens issued after this moment pass.
    let revoked_iat = claims.iat;
    state
        .user_revocations
        .write()
        .await
        .entry(user_id)
        .and_modify(|v| {
            if revoked_iat > *v {
                *v = revoked_iat;
            }
        })
        .or_insert(revoked_iat);

    Ok(Json(json!({ "ok": true })))
}

// ─── Me History (stub) ────────────────────────────────────────────────────────

/// GET /v1/auth/me/history — stub returning empty list (emulator has no login history).
pub async fn me_history(State(_state): State<EmulatorState>) -> Json<Value> {
    Json(json!({ "history": [] }))
}

// ─── Tenant Select ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantSelectRequest {
    pub tenant: String,
}

pub async fn tenant_select(
    State(state): State<EmulatorState>,
    req: Request,
) -> Result<(axum::http::HeaderMap, Json<Value>), EmulatorError> {
    // Extract refresh JWT from Authorization header ("Bearer projectId:refreshJwt")
    let token_str = extract_refresh_jwt(&req, None).ok_or(EmulatorError::Unauthorized)?;

    if state.revoked.read().await.is_revoked(&token_str) {
        return Err(EmulatorError::TokenExpired);
    }

    let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .map_err(|e| EmulatorError::Internal(e.to_string()))?;
    let body: TenantSelectRequest =
        serde_json::from_slice(&body_bytes).map_err(|_| EmulatorError::Unauthorized)?;

    let claims = validate_refresh_jwt(&*state.km().await, &token_str)?;
    let user_id = &claims.sub;

    let users = state.users.read().await;
    let user = users.load_by_user_id(user_id)?;

    // Verify user belongs to the requested tenant
    if !user.user_tenants.iter().any(|t| t.tenant_id == body.tenant) {
        return Err(EmulatorError::TenantNotFound);
    }

    // Verify the tenant itself still exists (e.g., not deleted after the user was provisioned)
    {
        let tenants = state.tenants.read().await;
        if tenants.load(&body.tenant).is_err() {
            return Err(EmulatorError::TenantNotFound);
        }
    }

    if user.status == "disabled" {
        return Err(EmulatorError::UserDisabled);
    }

    // Issue new session JWT with dct claim, plus a new refresh JWT
    let mut extra_claims = std::collections::HashMap::new();
    extra_claims.insert(
        "dct".to_string(),
        serde_json::Value::String(body.tenant.clone()),
    );

    let session_jwt = crate::jwt::token_generator::generate_session_jwt_with_extra(
        &*state.km().await,
        user,
        &state.config.project_id,
        state.config.session_ttl,
        &extra_claims,
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

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + state.config.session_ttl;
    let user_resp = serde_json::to_value(user.to_response()).unwrap();
    let cookies = build_auth_cookies(&session_jwt, &refresh_jwt, state.config.session_ttl);
    let body_resp = json!({
        "sessionJwt": session_jwt,
        "refreshJwt": refresh_jwt,
        "cookieDomain": "",
        "cookiePath": "/",
        "cookieMaxAge": state.config.session_ttl,
        "cookieExpiration": exp,
        "firstSeen": false,
        "user": user_resp
    });

    Ok((cookies, Json(body_resp)))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::EmulatorConfig,
        jwt::token_generator::generate_refresh_jwt,
        state::EmulatorState,
        store::user_store::new_user_id,
        types::{User, UserTenant},
    };

    async fn make_state() -> EmulatorState {
        EmulatorState::new(&EmulatorConfig::default())
            .await
            .unwrap()
    }

    async fn insert_user_with_tenant(
        state: &EmulatorState,
        login_id: &str,
        tenant_id: &str,
    ) -> (String, String) {
        let uid = new_user_id();
        let mut u = User::default();
        u.user_id = uid.clone();
        u.login_ids = vec![login_id.to_string()];
        u.email = Some(login_id.to_string());
        u.status = "enabled".into();
        u.user_tenants = vec![UserTenant {
            tenant_id: tenant_id.to_string(),
            ..Default::default()
        }];
        state.users.write().await.insert(u).unwrap();

        // Also create the tenant in the tenant store so tenant_select validates it.
        let _ = state.tenants.write().await.create(
            Some(tenant_id.to_string()),
            tenant_id.to_string(),
            vec![],
        );

        let refresh_jwt = generate_refresh_jwt(
            &*state.km().await,
            &uid,
            &state.config.project_id,
            state.config.refresh_ttl,
        )
        .unwrap();
        (uid, refresh_jwt)
    }

    // ─── me_history ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn me_history_returns_empty_list() {
        let state = make_state().await;
        let result = me_history(State(state)).await;
        let body = result.0;
        assert_eq!(body["history"], serde_json::json!([]));
    }

    // ─── tenant_select ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn tenant_select_valid_tenant_returns_tokens_with_dct() {
        let state = make_state().await;
        let (_, refresh_jwt) = insert_user_with_tenant(&state, "user@test.com", "tenant-1").await;

        // Build a fake Request with the JWT in the Authorization header and tenant in body
        let body_str = r#"{"tenant": "tenant-1"}"#;
        let req = axum::http::Request::builder()
            .method("POST")
            .header("Authorization", format!("Bearer {}", refresh_jwt))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body_str))
            .unwrap();

        let (_, Json(body)) = tenant_select(State(state), req).await.unwrap();
        let session_jwt = body["sessionJwt"].as_str().unwrap();
        // Decode claims to verify dct is present
        let parts: Vec<&str> = session_jwt.split('.').collect();
        let payload = String::from_utf8(
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
                .unwrap(),
        )
        .unwrap();
        let claims: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(claims["dct"], "tenant-1");
    }

    #[tokio::test]
    async fn tenant_select_unknown_tenant_returns_not_found() {
        let state = make_state().await;
        let (_, refresh_jwt) = insert_user_with_tenant(&state, "user2@test.com", "tenant-1").await;

        let body_str = r#"{"tenant": "other-tenant"}"#;
        let req = axum::http::Request::builder()
            .method("POST")
            .header("Authorization", format!("Bearer {}", refresh_jwt))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body_str))
            .unwrap();

        let err = tenant_select(State(state), req).await.unwrap_err();
        assert!(matches!(err, EmulatorError::TenantNotFound));
    }
}
