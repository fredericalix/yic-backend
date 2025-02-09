use actix_web::{get, HttpResponse, Responder, HttpRequest, Error};
use serde_json::json;
use crate::models::auth::{KeycloakConfig, UserInfo};
use crate::services::auth::validate_token;
use std::env;

#[utoipa::path(
    get,
    path = "/auth/config",
    tag = "auth",
    responses(
        (status = 200, description = "Keycloak configuration", body = KeycloakConfig)
    )
)]
#[get("/auth/config")]
pub async fn get_auth_config() -> impl Responder {
    let keycloak_url = env::var("CC_KEYCLOAK_URL")
        .expect("CC_KEYCLOAK_URL must be set");
    let realm = env::var("KEYCLOACK_REALM")
        .expect("KEYCLOACK_REALM must be set");
    let client_id = env::var("KEYCLOACK_CLIENTID")
        .expect("KEYCLOACK_CLIENTID must be set");

    let config = KeycloakConfig {
        url: keycloak_url.clone(),
        realm: realm.clone(),
        client_id,
        auth_endpoint: format!("{}/realms/{}/protocol/openid-connect/auth", keycloak_url, realm),
        token_endpoint: format!("{}/realms/{}/protocol/openid-connect/token", keycloak_url, realm),
        logout_endpoint: format!("{}/realms/{}/protocol/openid-connect/logout", keycloak_url, realm),
        userinfo_endpoint: format!("{}/realms/{}/protocol/openid-connect/userinfo", keycloak_url, realm),
    };

    HttpResponse::Ok().json(config)
}

#[utoipa::path(
    get,
    path = "/api/protected",
    tag = "api",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Access granted to protected resource", body = String),
        (status = 401, description = "Unauthorized")
    )
)]
#[get("/protected")]
pub async fn protected_route() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "message": "Hey, you made it to the protected route!"
    }))
}

#[utoipa::path(
    get,
    path = "/api/me",
    tag = "api",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "User information", body = UserInfo),
        (status = 401, description = "Unauthorized")
    )
)]
#[get("/me")]
pub async fn get_user_info(req: HttpRequest) -> Result<HttpResponse, Error> {
    if let Some(auth_header) = req.headers().get("Authorization") {
        let auth_str = auth_header.to_str().unwrap_or("");
        if auth_str.starts_with("Bearer ") {
            let token = &auth_str[7..];
            let claims = validate_token(token).await?;
            
            let user_info = UserInfo {
                sub: claims.sub,
                username: claims.username.unwrap_or_else(|| "unknown".to_string()),
                email: None,
                roles: vec![],
            };

            Ok(HttpResponse::Ok().json(user_info))
        } else {
            Err(actix_web::error::ErrorUnauthorized("Invalid token format"))
        }
    } else {
        Err(actix_web::error::ErrorUnauthorized("No authorization header"))
    }
} 