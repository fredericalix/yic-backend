use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    #[serde(rename = "preferred_username")]
    pub username: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    #[serde(rename = "resource_access")]
    pub resource_access: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UserInfo {
    pub sub: String,
    pub username: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct KeycloakConfig {
    pub url: String,
    pub realm: String,
    pub client_id: String,
    pub auth_endpoint: String,
    pub token_endpoint: String,
    pub logout_endpoint: String,
    pub userinfo_endpoint: String,
} 