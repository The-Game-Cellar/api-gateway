# API Gateway

> Single entry point for The Game Cellar frontend. Handles routing, JWT validation, CORS, and the local auth endpoints (authorize, callback, refresh, logout, account deletion). Passwords and email addresses are changed on Keycloak's own pages and never reach this service.

[![CI](https://github.com/The-Game-Cellar/api-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/The-Game-Cellar/api-gateway/actions/workflows/ci.yml)
![Java](https://img.shields.io/badge/Java-17-orange)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.0-brightgreen)
![License](https://img.shields.io/badge/License-MIT-blue)

**Port:** `8000`

## Responsibilities

- Route `/api/v1/games/**`, `/api/v1/library/**`, and `/api/v1/recommendations/**` to the matching backend service.
- Validate JWTs against the Keycloak realm via its JWKS endpoint.
- Host the local auth controller: it starts and completes the Authorization Code flow with PKCE, rotates refresh tokens, logs out, and changes email and password through the Keycloak Admin API.
- Issue and clear HttpOnly auth cookies so the frontend never holds raw JWTs in JavaScript.
- Apply per-IP rate limiting on `/auth/authorize` via Bucket4j.

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
- Sentry for error tracking (`sentry-spring-boot-4` + `sentry-logback`)

> Routes are defined programmatically in `GatewayRoutesConfig.java`. YAML-based routes do not work with Spring Cloud Gateway MVC 5.x and silently fail with `NoResourceFoundException`.

## API Endpoints

### Routed (forwarded to downstream services)

| Path                          | Target Service             |
|-------------------------------|----------------------------|
| `/api/v1/games/**`            | Game Service (8081)        |
| `/api/v1/platforms/**`        | Game Service (8081)        |
| `/api/v1/admin/rec/**`        | Recommendation Service (8083). `@Order(HIGHEST_PRECEDENCE)` so this prefix wins over the broader `/api/v1/admin/**` route below. |
| `/api/v1/admin/**`            | Game Service (8081)        |
| `/api/v1/library/**`          | Library Service (8082)     |
| `/api/v1/recommendations/**`  | Recommendation Service (8083) |

`/internal/**` paths on downstream services are intentionally not routed here. Service-to-service calls go directly over the docker network with the `X-Internal-Token` shared secret.

### Handled locally

| Method | Path                              | Description                                                 |
|--------|-----------------------------------|-------------------------------------------------------------|
| GET    | `/api/v1/auth/authorize`          | Starts Authorization Code + PKCE. Stores verifier, state, nonce and intent in the session, redirects to Keycloak. `?register=true` opens the sign-up page instead of the login page. `?intent=UPDATE_PASSWORD` and `?intent=UPDATE_EMAIL` add `kc_action` so Keycloak runs the change itself; `?intent=DELETE_ACCOUNT` only forces a fresh sign-in. Every intent other than a plain login sends `prompt=login` and `max_age=0`. |
| GET    | `/api/v1/auth/callback`           | Keycloak redirect target. Validates state and nonce, exchanges the code, sets cookies. Routes on the stored intent: a login lands on the dashboard, an action lands on `/profile` carrying Keycloak's `kc_action_status`, and a completed re-authentication records a single-use marker for account deletion. |
| POST   | `/api/v1/auth/logout`             | Revokes the refresh token and clears cookies.               |
| POST   | `/api/v1/auth/refresh`            | Refresh-token grant. Rotates cookies.                       |
| GET    | `/api/v1/auth/me`                 | Reads the access-token cookie and returns userInfo.         |
| DELETE | `/api/v1/auth/account`            | Disables the Keycloak user and ends its sessions, purges library data (which writes the deletion ledger), deletes the Keycloak user, then closes the ledger row. A failure before the purge is a `502` with nothing deleted (a failed purge re-enables the user); a failure after it is a `202`, and the scheduled retry job finishes the identity delete. Requires a re-authentication completed through `/authorize?intent=DELETE_ACCOUNT` within the last five minutes; takes no request body. |

### Scheduled

`AccountDeletionRetryJob` runs every `ACCOUNT_DELETION_RETRY_DELAY_MS`, reads `GET /internal/library/account-deletions/pending` from library-service, and for each row disables and deletes the Keycloak user (a `404` counts as deleted) and posts `.../{userId}/complete`. Every `ACCOUNT_DELETION_RETRY_MAX_ATTEMPTS` failed attempts on one row logs at ERROR, which reaches Sentry.

## Configuration

| Variable                       | Default                                       | Purpose                                                            |
|--------------------------------|-----------------------------------------------|--------------------------------------------------------------------|
| `GATEWAY_PORT`                 | `8000`                                        | Service port                                                       |
| `KEYCLOAK_AUTH_SERVER_URL`     | `http://localhost:8080`                       | Keycloak base URL for JWKS and server-side token calls             |
| `KEYCLOAK_ISSUER_URI`          | `http://localhost:8080/realms/game-cellar`    | Expected `iss` on every incoming token. Must be the origin the browser reaches, not the one the gateway dials |
| `KEYCLOAK_PUBLIC_URL`          | value of `KEYCLOAK_AUTH_SERVER_URL`           | Browser-facing Keycloak origin used for the authorization redirect |
| `AUTH_REDIRECT_URI`            | `http://localhost:8000/api/v1/auth/callback`  | Must match a Valid Redirect URI on the realm client exactly        |
| `APP_BASE_URL`                 | `http://localhost:5173`                       | Where the gateway sends the browser after a completed login        |
| `KEYCLOAK_REALM`               | `game-cellar`                                 | Realm name                                                         |
| `KEYCLOAK_CLIENT_ID`           | `game-cellar-client`                          | Public client for the code flow, and the expected `azp` on incoming tokens |
| `GATEWAY_ADMIN_CLIENT_ID`      | `gateway-admin`                               | Service-account client for the Admin REST calls made on account deletion: disable, logout, delete |
| `GATEWAY_ADMIN_CLIENT_SECRET`  | _none_                                        | Service-account secret (must have `realm-management/manage-users`) |
| `INTERNAL_SERVICE_TOKEN`       | (empty)                                       | Shared secret for library-service's `/internal/**` paths, where the account deletion ledger lives. Empty means the ledger cannot be read or closed. |
| `ACCOUNT_DELETION_RETRY_DELAY_MS` | `60000`                                    | Interval of the deletion retry job                                 |
| `ACCOUNT_DELETION_RETRY_INITIAL_DELAY_MS` | `60000`                            | Delay before the job's first run after start                       |
| `ACCOUNT_DELETION_RETRY_MAX_ATTEMPTS` | `10`                                   | Failed attempts on one row between ERROR-level escalations         |
| `GAME_SERVICE_URL`             | `http://localhost:8081`                       | Downstream service                                                 |
| `LIBRARY_SERVICE_URL`          | `http://localhost:8082`                       | Downstream service                                                 |
| `RECOMMENDATION_SERVICE_URL`   | `http://localhost:8083`                       | Downstream service                                                 |
| `ALLOWED_ORIGINS`              | `http://localhost:5173`                       | CORS whitelist                                                     |
| `COOKIE_SECURE`                | `false`                                       | Set to `true` in production                                        |
| `RECOMMENDATION_RATELIMIT_DISTRIBUTED` | `true`                                | Property `recommendation.ratelimit.distributed`. When `true`, Bucket4j uses Redis (`bucket4j_jdk17-lettuce`). When `false`, falls back to in-memory Caffeine (single-instance ceiling). |
| `REDIS_HOST`                   | `localhost`                                   | Redis host for distributed rate-limit buckets                      |
| `REDIS_PORT`                   | `6379`                                        | Redis port                                                         |
| `REDIS_PASSWORD`               | (required when Redis used)                    | Redis password                                                     |
| `RATE_LIMIT_TRUSTED_PROXIES`   | (empty)                                       | Comma-separated IPs/CIDRs of proxies allowed to set `X-Forwarded-For`. Empty means the header is ignored and the socket address is used. Set to the edge proxy ranges (e.g. Cloudflare) when deployed behind one. |
| `SENTRY_DSN`                   | (empty)                                       | Sentry ingest endpoint. Empty makes the SDK a no-op, so local runs and tests send nothing. Set in production only. |
| `SENTRY_ENVIRONMENT`           | `local`                                       | Environment tag on every Sentry event                              |
| `SENTRY_RELEASE`               | (empty)                                       | Commit sha, baked into the image at build time so Sentry can group regressions by deploy |

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

Hermetic: no Keycloak, Redis or downstream service is needed. A JDK `HttpServer` stub per outbound target (Keycloak, library-service and the three proxy targets) records what the gateway sent and answers what the test scripted, and the `JwtDecoder` is a mock that maps token strings to claims. Covered through MockMvc: the security chain (cookie and bearer resolution, the admin role, 401 and 403 paths), every route prefix landing on the right service with its query string, CORS preflight and actual requests, the request-id filter, both rate limiters in their own context, and the full auth flow: `authorize` per intent, `callback` with PKCE verified against the challenge that went out, `refresh`, `logout`, `me` and `account` including purge-before-identity ordering and the admin-token retry. `TokenValidatorTest` covers issuer, `azp`, expiry and not-before on the validator the decoder uses.

## Security

- JWTs are validated against the live Keycloak JWKS endpoint on every request.
- The gateway never accepts a `user_id` from a request body; downstream services extract it from the JWT `sub` claim.
- Access and refresh tokens live in HttpOnly cookies. The frontend cannot read them from JavaScript.
- `/api/v1/auth/authorize` and `/api/v1/recommendations/**` are rate-limited per IP via Bucket4j.

## License

[MIT](./LICENSE)
