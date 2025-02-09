use actix_web::Error;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use log::{info, error, warn};
use std::env;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use crate::models::auth::Claims;

pub async fn validate_token(raw_token: &str) -> Result<Claims, Error> {
    let token = raw_token.split('"').find(|s| s.starts_with("ey")).ok_or_else(|| {
        error!("Could not find JWT token in authorization header");
        actix_web::error::ErrorUnauthorized("Invalid token format")
    })?;

    info!("Processing JWT token: {}", token);

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        error!("Invalid JWT format - expected 3 parts, got {}", parts.len());
        return Err(actix_web::error::ErrorUnauthorized("Invalid token format"));
    }

    let keycloak_url = env::var("CC_KEYCLOAK_URL")
        .expect("CC_KEYCLOAK_URL must be set");
    let realm = env::var("KEYCLOACK_REALM")
        .expect("KEYCLOACK_REALM must be set");

    info!("Validating token with Keycloak at {}", keycloak_url);

    let cert_url = format!("{}/realms/{}/protocol/openid-connect/certs", keycloak_url, realm);
    
    let cert = reqwest::get(&cert_url)
        .await
        .map_err(|e| {
            error!("Failed to fetch Keycloak certificate: {}", e);
            actix_web::error::ErrorInternalServerError(e)
        })?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| {
            error!("Failed to parse Keycloak certificate: {}", e);
            actix_web::error::ErrorInternalServerError(e)
        })?;

    let public_key = cert["keys"][0]["x5c"][0]
        .as_str()
        .ok_or_else(|| {
            error!("Missing x5c field in certificate");
            actix_web::error::ErrorInternalServerError("Invalid cert format")
        })?;

    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        public_key
            .chars()
            .collect::<Vec<char>>()
            .chunks(64)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join("\n")
    );

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false; // Temporarily disabled expiration check while testing
    validation.set_audience(&["example-realm", "broker", "account"]);
    
    let decoding_key = DecodingKey::from_rsa_pem(pem.as_bytes())
        .map_err(|e| {
            error!("Failed to create decoding key: {}", e);
            actix_web::error::ErrorInternalServerError(e)
        })?;

    // Debug decode attempts
    info!("Trying to decode header: {}", parts[0]);
    let header = URL_SAFE_NO_PAD.decode(parts[0])
        .map_err(|e| {
            error!("Failed to decode header: {}", e);
            actix_web::error::ErrorUnauthorized(e)
        })?;
    info!("Header decoded successfully: {}", String::from_utf8_lossy(&header));

    info!("Trying to decode payload: {}", parts[1]);
    let payload = URL_SAFE_NO_PAD.decode(parts[1])
        .map_err(|e| {
            error!("Failed to decode payload: {}", e);
            actix_web::error::ErrorUnauthorized(e)
        })?;
    info!("Payload decoded successfully: {}", String::from_utf8_lossy(&payload));
    
    match decode::<Claims>(token, &decoding_key, &validation) {
        Ok(token_data) => {
            info!("Token successfully validated for user: {:?}", token_data.claims.username);
            Ok(token_data.claims)
        },
        Err(e) => {
            warn!("Token validation failed: {}", e);
            Err(actix_web::error::ErrorUnauthorized(e))
        }
    }
} 