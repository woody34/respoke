use axum::http::header::SET_COOKIE;
use axum::http::HeaderMap;

/// Build Set-Cookie headers for DS (session) and DSR (refresh) cookies.
pub fn build_auth_cookies(session_jwt: &str, refresh_jwt: &str, session_ttl: u64) -> HeaderMap {
    let mut headers = HeaderMap::new();

    let ds = format!(
        "DS={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        session_jwt, session_ttl
    );
    let dsr = format!("DSR={}; HttpOnly; SameSite=Lax; Path=/", refresh_jwt);

    headers.append(SET_COOKIE, ds.parse().expect("valid DS cookie"));
    headers.append(SET_COOKIE, dsr.parse().expect("valid DSR cookie"));
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_ds_and_dsr_cookies() {
        let headers = build_auth_cookies("session.tok", "refresh.tok", 3600);
        let cookies: Vec<&str> = headers
            .get_all(SET_COOKIE)
            .into_iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookies.len(), 2);
        assert!(cookies.iter().any(|c| c.starts_with("DS=")));
        assert!(cookies.iter().any(|c| c.starts_with("DSR=")));
    }

    #[test]
    fn ds_cookie_has_required_attributes() {
        let headers = build_auth_cookies("s", "r", 3600);
        let ds = headers
            .get_all(SET_COOKIE)
            .into_iter()
            .map(|v| v.to_str().unwrap().to_string())
            .find(|c| c.starts_with("DS="))
            .unwrap();
        assert!(ds.contains("HttpOnly"));
        assert!(ds.contains("SameSite=Lax"));
        assert!(ds.contains("Path=/"));
    }
}
