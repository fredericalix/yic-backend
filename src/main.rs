use actix_web::{
    middleware::Logger,
    web,
    App,
    HttpServer,
};
use env_logger::Env;
use log::info;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use utoipa::openapi::security::HttpAuthScheme;

use crate::routes::{
    health::health_check,
    auth::{get_auth_config, protected_route, get_user_info},
};
use crate::routes::health::__path_health_check;
use crate::routes::auth::{
    __path_get_auth_config,
    __path_protected_route,
    __path_get_user_info
};

pub mod models;
pub mod routes;
pub mod services;
pub mod middleware;

#[derive(OpenApi)]
#[openapi(
    paths(
        health_check,
        get_auth_config,
        protected_route,
        get_user_info
    ),
    components(
        schemas(models::auth::Claims, models::auth::UserInfo, models::auth::KeycloakConfig)
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
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let openapi = ApiDoc::openapi();

    info!("Starting server at http://localhost:8080");

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-docs/openapi.json", openapi.clone()),
            )
            .service(health_check)
            .service(get_auth_config)
            .service(
                web::scope("/api")
                    .wrap(middleware::auth::Auth)
                    .service(protected_route)
                    .service(get_user_info)
            )
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
