use actix_web::{
    get, 
    web, 
    App, 
    HttpResponse, 
    HttpServer, 
    Responder, 
    Error,
    dev::{ServiceRequest, Service, ServiceResponse, Transform},
    HttpRequest
};
use serde_json::json;
use std::env;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use actix_web::middleware::Logger;
use std::future::{ready, Ready, Future};
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    #[serde(rename = "preferred_username")]
    username: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserInfo {
    sub: String,
    username: String,
    email: Option<String>,
    roles: Vec<String>,
}

#[derive(Debug, Serialize)]
struct KeycloakConfig {
    url: String,
    realm: String,
    client_id: String,
    auth_endpoint: String,
    token_endpoint: String,
    logout_endpoint: String,
    userinfo_endpoint: String,
}

async fn validate_token(token: &str) -> Result<Claims, Error> {
    let keycloak_url = env::var("CC_KEYCLOAK_URL")
        .expect("CC_KEYCLOAK_URL must be set");
    let realm = env::var("KEYCLOACK_REALM")
        .expect("KEYCLOACK_REALM must be set");

    let cert_url = format!("{}/realms/{}/protocol/openid-connect/certs", keycloak_url, realm);
    
    let cert = reqwest::get(&cert_url)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let key = cert["keys"][0]["x5c"][0]
        .as_str()
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("Invalid cert format"))?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_base64_secret(key).unwrap(),
        &Validation::new(Algorithm::RS256),
    ).map_err(|e| actix_web::error::ErrorUnauthorized(e))?;

    Ok(token_data.claims)
}

// Créons un middleware plus propre avec la structure appropriée
pub struct AuthMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let auth_header = req.headers().get("Authorization").cloned();
        let fut = self.service.call(req);

        Box::pin(async move {
            if let Some(auth_header) = auth_header {
                let auth_str = auth_header.to_str().unwrap_or("");
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..];
                    validate_token(token).await?;
                    fut.await
                } else {
                    Err(actix_web::error::ErrorUnauthorized("Invalid token format"))
                }
            } else {
                Err(actix_web::error::ErrorUnauthorized("No authorization header"))
            }
        })
    }
}

// Créons un Transform pour notre middleware
pub struct Auth;

impl<S, B> Transform<S, ServiceRequest> for Auth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddleware { service }))
    }
}

#[get("/protected")]
async fn protected_route() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "message": "Cette route est protégée!"
    }))
}

#[get("/me")]
async fn get_user_info(req: HttpRequest) -> Result<HttpResponse, Error> {
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

#[get("/")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "ok, service online"
    }))
}

#[get("/auth/config")]
async fn get_auth_config() -> impl Responder {
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    dotenv::dotenv().ok();

    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let port = port.parse::<u16>().expect("PORT doit être un nombre valide");

    println!("Serveur démarré sur le port {}", port);

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(health_check)
            .service(get_auth_config)
            .service(
                web::scope("/api")
                    .wrap(Auth)
                    .service(protected_route)
                    .service(get_user_info)
            )
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
