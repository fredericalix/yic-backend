# YourITCity Backend API

Backend service for YourITCity, built with Rust and Actix-web.

## Prerequisites

- Rust (latest stable version)
- Keycloack server running on Clever Cloud
- Environment variables properly configured (see Configuration section)

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/yourusername/yic-backend.git
cd yic-backend
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Build and run:
```bash
cargo build
cargo run
```

The server will start at `http://localhost:8080`

## Configuration

Required environment variables:

- `CC_KEYCLOAK_URL`: URL of your Keycloak instance
- `KEYCLOACK_REALM` : Keycloak realm name
- `KEYCLOACK_CLIENTID`: Client ID for your application
- `PORT`: Server port (optional, defaults to 8080)

## API Documentation

OpenAPI documentation is available at:
- Swagger UI: `http://localhost:8080/swagger-ui/`
- OpenAPI JSON: `http://localhost:8080/api-docs/openapi.json`

## API Endpoints

### Public Routes
- `GET /`: Health check
- `GET /auth/config`: Keycloak configuration
- `GET /swagger-ui/`: API documentation
- `GET /api-docs/openapi.json`: OpenAPI specification

### Protected Routes (require Bearer token)
- `GET /api/protected`: Test protected route
- `GET /api/me`: Get user information

## Authentication

The API uses Keycloak for authentication. To access protected routes:

1. Get a token from Keycloak using the configuration from `/auth/config`
2. Include the token in requests using the Authorization header:
```
Authorization: Bearer <your-token>
```

## Development

### Running Tests
```bash
cargo test
```

### Code Style
```bash
cargo fmt
cargo clippy
```

## Project Structure

```
src/
— main.rs           # Application entry point
— models/           # Data structures
— routes/           # API route handlers
— services/          # Business logic
— middleware/       # Custom middleware (auth, etc.)
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the BSD 3-Clause License - see the LICENSE file for details
