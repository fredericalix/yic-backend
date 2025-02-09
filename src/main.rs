use actix_web::{
    get, 
    web, 
    App, 
    HttpResponse, 
    HttpServer, 
    Responder, 
    Error,
    dev::{ServiceRequest, Service, ServiceResponse, Transform},
    HttpRequest,
    middleware::Logger
};
use serde_json::json;
use std::env;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use log::{info, error, warn};
use std::future::{ready, Ready, Future};
use std::pin::Pin;
use std::task::{Context, Poll};
use utoipa::OpenApi;
use utoipa::openapi::security::{SecurityScheme, HttpBuilder, HttpAuthScheme};
use utoipa_swagger_ui::SwaggerUi;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
struct Claims {
    sub: String,
    exp: usize,
    #[serde(rename = "preferred_username")]
    username: Option<String>,
    email: Option<String>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    #[serde(rename = "resource_access")]
    resource_access: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct UserInfo {
    sub: String,
    username: String,
    email: Option<String>,
    roles: Vec<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
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

    // Log the certificate for debugging
    info!("Received certificate: {}", serde_json::to_string_pretty(&cert).unwrap());

    // Récupère la clé publique directement du champ 'n' (modulus)
    let n = cert["keys"][0]["n"]
        .as_str()
        .ok_or_else(|| {
            error!("Missing 'n' field in certificate");
            actix_web::error::ErrorInternalServerError("Invalid cert format")
        })?;
    
    let e = cert["keys"][0]["e"]
        .as_str()
        .ok_or_else(|| {
            error!("Missing 'e' field in certificate");
            actix_web::error::ErrorInternalServerError("Invalid cert format")
        })?;

    // Décode les composants de la clé
    let n = BASE64.decode(n).map_err(|e| {
        error!("Failed to decode 'n' component: {}", e);
        actix_web::error::ErrorInternalServerError(e)
    })?;

    let e = BASE64.decode(e).map_err(|e| {
        error!("Failed to decode 'e' component: {}", e);
        actix_web::error::ErrorInternalServerError(e)
    })?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false; // Optionnel: désactive la validation de l'expiration pour les tests
    validation.set_audience(&["example-realm", "broker", "account"]);
    
    let decoding_key = DecodingKey::from_rsa_raw_components(&n, &e);
    
    match decode::<Claims>(
        token,
        &decoding_key,
        &validation,
    ) {
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
        let path = req.path().to_string();
        let method = req.method().to_string();
        info!("Incoming request: {} {}", method, path);

        let auth_header = req.headers().get("Authorization").cloned();
        let fut = self.service.call(req);

        Box::pin(async move {
            if let Some(auth_header) = auth_header {
                let auth_str = auth_header.to_str().unwrap_or("");
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..];
                    match validate_token(token).await {
                        Ok(_) => {
                            info!("Request authenticated: {} {}", method, path);
                            fut.await
                        },
                        Err(e) => {
                            warn!("Authentication failed for {} {}: {}", method, path, e);
                            Err(e)
                        }
                    }
                } else {
                    warn!("Invalid token format for {} {}", method, path);
                    Err(actix_web::error::ErrorUnauthorized("Invalid token format"))
                }
            } else {
                warn!("No authorization header for {} {}", method, path);
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

// Ajoutez cette struct pour la documentation OpenAPI
#[derive(OpenApi)]
#[openapi(
    paths(
        health_check,
        get_auth_config,
        protected_route,
        get_user_info
    ),
    components(
        schemas(UserInfo, KeycloakConfig)
    ),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "auth", description = "Authentication related endpoints"),
        (name = "api", description = "Protected API endpoints")
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

// Modifiez vos routes pour ajouter la documentation
#[utoipa::path(
    get,
    path = "/",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = String)
    )
)]
#[get("/")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "ok, service online"
    }))
}

#[utoipa::path(
    get,
    path = "/auth/config",
    tag = "auth",
    responses(
        (status = 200, description = "Keycloak configuration", body = KeycloakConfig)
    )
)]
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
async fn protected_route() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "message": "Cette route est protégée!"
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Configure le format des logs
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    dotenv::dotenv().ok();

    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let port = port.parse::<u16>().expect("PORT doit être un nombre valide");

    info!("Starting server on port {}", port);

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::new("%a %r %s %b %{Referer}i %{User-Agent}i %T"))
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-docs/openapi.json", ApiDoc::openapi())
            )
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
