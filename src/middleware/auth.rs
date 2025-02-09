use actix_web::{
    dev::{ServiceRequest, Service, ServiceResponse, Transform},
    Error,
};
use std::future::{ready, Ready, Future};
use std::pin::Pin;
use std::task::{Context, Poll};
use log::{info, warn};
use crate::services::auth::validate_token;

// Add a list of public paths that don't need authentication
const PUBLIC_PATHS: [&str; 4] = [
    "/",
    "/swagger-ui",
    "/api-docs",
    "/auth/config",
];

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

        // Check if the path is public
        if PUBLIC_PATHS.iter().any(|public_path| path.starts_with(public_path)) {
            info!("Public route accessed: {} {}", method, path);
            return Box::pin(self.service.call(req));
        }

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