use actix_web::{get, HttpResponse, Responder};
use serde_json::json;

#[utoipa::path(
    get,
    path = "/",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = String)
    )
)]
#[get("/")]
pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "ok, service online"
    }))
} 