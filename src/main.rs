use actix_web::{get, App, HttpResponse, HttpServer, Responder};
use serde_json::json;
use std::env;

#[get("/")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "ok, service online"
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // Récupère le port depuis la variable d'environnement PORT ou utilise 8080 par défaut
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let port = port.parse::<u16>().expect("PORT doit être un nombre valide");

    println!("Serveur démarré sur le port {}", port);

    HttpServer::new(|| {
        App::new()
            .service(health_check)
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
