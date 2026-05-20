# API Gateway

> Single entry point for The Game Cellar frontend. Handles routing, JWT validation, CORS, and the local auth endpoints (login, register, refresh, logout, change-email, change-password).

![Java](https://img.shields.io/badge/Java-17-orange)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.0-brightgreen)
![License](https://img.shields.io/badge/License-MIT-blue)

**Port:** `8000`

## Responsibilities

- Route `/api/v1/games/**`, `/api/v1/library/**`, and `/api/v1/recommendations/**` to the matching backend service.
- Validate JWTs against the Keycloak realm via its JWKS endpoint.
- Host the local auth controller: password-grant login, custom registration through the Keycloak Admin API, refresh-token rotation, logout, change-email, change-password.
- Issue and clear HttpOnly auth cookies so the frontend never holds raw JWTs in JavaScript.
- Apply per-IP rate limiting on `/auth/login` via Bucket4j.

## Position in the System

```
Frontend (5173)
      |
   API Gateway (8000)  <->  Keycloak (8080)
      |
   +--+----------------+----------------+
Game Service   Library Service   Recommendation Service
   (8081)         (8082)              (8083)
```

The gateway is the only service the frontend talks to. It forwards the user's JWT to downstream services and acts as the OAuth client when interacting with Keycloak.

## Tech Stack

- Java 17, Spring Boot 4.0
- Spring Cloud Gateway MVC 5.x (servlet-based, not reactive Netty)
- Spring Security OAuth 2 Resource Server for JWT validation
- Bucket4j for per-IP rate limiting
- Spring Boot Actuator for `/actuator/health`

> Routes are defined programmatically in `GatewayRoutesConfig.java`. YAML-based routes do not work with Spring Cloud Gateway MVC 5.x and silently fail with `NoResourceFoundException`.

## API Endpoints

### Routed (forwarded to downstream services)

| Path                          | Target Service             |
|-------------------------------|----------------------------|
| `/api/v1/games/**`            | Game Service (8081)        |
| `/api/v1/library/**`          | Library Service (8082)     |
| `/api/v1/recommendations/**`  | Recommendation Service (8083) |

### Handled locally

| Method | Path                              | Description                                                 |
|--------|-----------------------------------|-------------------------------------------------------------|
| POST   | `/api/v1/auth/login`              | Password grant. Sets HttpOnly access + refresh cookies.     |
| POST   | `/api/v1/auth/register`           | Creates a Keycloak user via Admin API, then auto-logs in.   |
| POST   | `/api/v1/auth/logout`             | Revokes the refresh token and clears cookies.               |
| POST   | `/api/v1/auth/refresh`            | Refresh-token grant. Rotates cookies.                       |
| GET    | `/api/v1/auth/me`                 | Reads the access-token cookie and returns userInfo.         |
| PUT    | `/api/v1/auth/change-password`    | Re-verifies current password, then admin reset-password.    |
| PUT    | `/api/v1/auth/change-email`       | Re-verifies current password, then admin user update.       |

## Configuration

| Variable                       | Default                                       | Purpose                                                            |
|--------------------------------|-----------------------------------------------|--------------------------------------------------------------------|
| `GATEWAY_PORT`                 | `8000`                                        | Service port                                                       |
| `KEYCLOAK_AUTH_SERVER_URL`     | `http://localhost:8080`                       | Keycloak base URL for JWKS                                         |
| `KEYCLOAK_REALM`               | `game-cellar`                                 | Realm name                                                         |
| `KEYCLOAK_CLIENT_ID`           | `game-cellar-client`                          | Public client for password grant                                   |
| `GATEWAY_ADMIN_CLIENT_ID`      | `gateway-admin`                               | Service-account client for user registration                       |
| `GATEWAY_ADMIN_CLIENT_SECRET`  | _none_                                        | Service-account secret (must have `realm-management/manage-users`) |
| `GAME_SERVICE_URL`             | `http://localhost:8081`                       | Downstream service                                                 |
| `LIBRARY_SERVICE_URL`          | `http://localhost:8082`                       | Downstream service                                                 |
| `RECOMMENDATION_SERVICE_URL`   | `http://localhost:8083`                       | Downstream service                                                 |
| `ALLOWED_ORIGINS`              | `http://localhost:5173`                       | CORS whitelist                                                     |
| `COOKIE_SECURE`                | `false`                                       | Set to `true` in production                                        |

Values are loaded from a root-level `.env` file in development. Secrets must never be hardcoded.

## Run Locally

### Prerequisites

- Java 17+
- A running Keycloak instance on port 8080 with the `game-cellar` realm + `gateway-admin` service-account client configured
- (Optional) The other three backend services running, if you want end-to-end routing

### Direct

```bash
./mvnw spring-boot:run
```

### Via Docker Compose (preferred)

From the project root one directory up:

```bash
docker compose up api-gateway
```

`depends_on: keycloak: service_healthy` ensures the gateway only boots after Keycloak is ready.

## Tests

```bash
./mvnw test
```

Covers the auth controller, JWT validation filter, rate-limit interceptor, and an end-to-end `FullFlowIntegrationTest`.

## Security

- JWTs are validated against the live Keycloak JWKS endpoint on every request.
- The gateway never accepts a `user_id` from a request body; downstream services extract it from the JWT `sub` claim.
- Access and refresh tokens live in HttpOnly cookies. The frontend cannot read them from JavaScript.
- `/auth/login` and `/auth/register` are rate-limited per IP via Bucket4j.

## License

[MIT](./LICENSE)
