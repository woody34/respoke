# Rescope

A standalone Rust emulator for the Descope authentication API. Built because Descope didn't ship one — use it for local development and testing without hitting the real Descope cloud service.

## Why Rescope?

Descope is a great managed auth platform, but it has no local development story. Every test that touches auth — signup, login, token validation, session refresh — requires a live network request to Descope's cloud. Rescope changes that.

- **Fast feedback loops.** Auth flows complete in milliseconds against a local binary instead of roundtripping to the cloud.
- **No API rate limits.** Run thousands of integration tests without worrying about hitting Descope's rate caps.
- **Fully offline.** Works on planes, coffee shops, and CI runners with no internet access.
- **Deterministic state.** Each test starts from a clean slate via `POST /emulator/reset`. No leaked users, tokens, or sessions between runs.
- **Real API surface.** Rescope speaks the same HTTP API as Descope — the same SDK code, the same JWT verification, the same management endpoints work against it unchanged.
- **Admin UI included.** Inspect users, OTP codes, access keys, roles, tenants, identity providers, and auth methods through a built-in web interface at the root URL `/`.
- **SSO testing without an IdP.** Emulate OIDC and SAML identity providers locally — no Okta, Azure AD, or Auth0 account required.

### AI Agents and the Case for a Sandbox

The rise of AI coding agents — tools that autonomously write, run, and iterate on code — introduces a new and underappreciated risk when those agents are pointed at live cloud services.

Auth APIs are a particularly sensitive target. When an AI agent runs tests or exploratory flows against a live Descope project, it operates with real credentials: management API keys that can create and delete users, session tokens that authenticate actual accounts, and API routes that trigger real side effects. Security researchers have documented several classes of risk this creates:

- **Overprivileged credentials.** AI agents are frequently granted broad API access to function effectively. If an agent's context is compromised via prompt injection or tool misuse, those credentials become an attack vector for lateral movement inside your cloud environment.
- **Credential exposure.** Because agents operate autonomously and often log intermediate state, long-lived API keys and session tokens can surface in logs, chat histories, or intermediate files — far outside the boundaries their owners intended.
- **Unintended side effects at scale.** An agent iterating rapidly can issue thousands of API calls against a live service, creating real users, generating real tokens, modifying real configuration — all in an environment shared with production data.
- **Supply chain trust.** Agents consume external tools, packages, and instructions. A compromised dependency or malicious prompt can redirect an agent to exfiltrate tokens or probe auth endpoints it was never intended to touch.

These aren't hypothetical concerns. In 2025, security firms documented AI-assisted attacks that used stolen cloud credentials and session tokens to probe thousands of API endpoints simultaneously, outpacing conventional detection systems. OWASP's Top 10 for Agentic Applications explicitly calls out inadequate sandboxing as a primary risk category.

**Rescope is a direct response to this.** When your AI agent — whether it's a test runner, a coding assistant exercising auth flows, or an automated pipeline — runs against Rescope instead of Descope's cloud, it operates in a fully isolated sandbox:

- No real credentials leave your machine
- No real users or tokens are created in your production project
- No API keys with cloud-level permissions are ever in play
- State resets completely between runs, leaving no residual data to exfiltrate

As agentic AI becomes a standard part of the development workflow, a local auth sandbox stops being a convenience and starts being a security requirement.

## Quick Start

### Binary Download

Download the latest release for your platform from [GitHub Releases](https://github.com/<your-username>/descope-emulator/releases/latest):

```bash
# macOS (Apple Silicon)
curl -sL https://github.com/<your-username>/descope-emulator/releases/latest/download/rescope-aarch64-apple-darwin.tar.gz | tar xz
./rescope

# macOS (Intel)
curl -sL https://github.com/<your-username>/descope-emulator/releases/latest/download/rescope-x86_64-apple-darwin.tar.gz | tar xz
./rescope

# Linux (x86_64)
curl -sL https://github.com/<your-username>/descope-emulator/releases/latest/download/rescope-x86_64-unknown-linux-gnu.tar.gz | tar xz
./rescope

# Linux (ARM64)
curl -sL https://github.com/<your-username>/descope-emulator/releases/latest/download/rescope-aarch64-unknown-linux-gnu.tar.gz | tar xz
./rescope
```

### From Source

```bash
# Clone and build
git clone https://github.com/<your-username>/descope-emulator.git
cd descope-emulator
npm install

# Start API + UI in development mode
npm run dev

# Or build a release binary
npx nx run api:build-release
./apps/api/target/release/rescope

# With a seed file
DESCOPE_EMULATOR_SEED_FILE=./seed.json ./rescope

# Custom port
DESCOPE_EMULATOR_PORT=3001 ./rescope
```

## Project Structure

Rescope is structured as an Nx monorepo:

```
/
├── apps/
│   ├── api/                  ← Rust backend (Axum)
│   ├── ui/                   ← React/Vite admin UI
│   ├── integration-api/      ← HTTP integration tests (Vitest)
│   ├── integration-sdk-js/   ← JS SDK integration tests
│   └── integration-sdk-nodejs/ ← Node SDK integration tests
├── libs/                     ← Shared libraries (future)
├── Cargo.toml                ← Cargo workspace
└── nx.json                   ← Nx workspace config
```

### Nx commands

| Command | Description |
|---|---|
| `npm run dev` | Start API + UI in parallel (dev mode) |
| `npm run build` | Build API (cargo) + UI (vite) |
| `npm run test` | Run unit + API integration + E2E tests |
| `npm run lint` | Clippy + ESLint |
| `npm run format` | `cargo fmt` + Prettier |
| `npm run graph` | Open the Nx project dependency graph |

## Environment Variables

| Variable                          | Default            | Description                                                  |
| --------------------------------- | ------------------ | ------------------------------------------------------------ |
| `DESCOPE_EMULATOR_PORT`           | `4500`             | HTTP port                                                    |
| `DESCOPE_PROJECT_ID`              | `emulator-project` | Project ID in JWT `iss` claim and management auth            |
| `DESCOPE_MANAGEMENT_KEY`          | `emulator-key`     | Management API key (`Authorization: Bearer <project>:<key>`) |
| `DESCOPE_EMULATOR_SESSION_TTL`    | `3600`             | Session JWT TTL in seconds                                   |
| `DESCOPE_EMULATOR_REFRESH_TTL`    | `2592000`          | Refresh JWT TTL in seconds                                   |
| `DESCOPE_EMULATOR_SEED_FILE`      | _(none)_           | Path to JSON seed file                                       |
| `DESCOPE_EMULATOR_KEY_FILE`       | _(none)_           | Path to PKCS8 PEM private key (auto-generated if absent)     |
| `DESCOPE_EMULATOR_CONNECTOR_MODE` | _(none / log)_     | Connector mode: `log` (default) or `invoke` (real HTTP)      |

## Seed File Format

```json
{
  "tenants": [
    {
      "id": "acme",
      "name": "Acme Corp",
      "domains": ["acme.com"],
      "authType": "saml"
    }
  ],
  "users": [
    {
      "loginId": "alice@acme.com",
      "email": "alice@acme.com",
      "name": "Alice",
      "password": "Secret123!",
      "verifiedEmail": true,
      "tenantIds": ["acme"],
      "roleNames": ["admin"],
      "isTestUser": false,
      "customAttributes": { "department": "engineering" }
    }
  ],
  "idpEmulators": [
    {
      "protocol": "oidc",
      "displayName": "Mock Okta",
      "tenantId": "acme",
      "attributeMapping": { "email": "user.email", "name": "user.name" }
    }
  ]
}
```

`POST /emulator/reset` clears all state and re-applies the seed file (if configured).

## API Endpoints

### Emulator / Infrastructure

| Method | Path                        | Description                              |
| ------ | --------------------------- | ---------------------------------------- |
| `GET`  | `/health`                   | Health check                             |
| `POST` | `/emulator/reset`           | Reset all runtime state (+ re-apply seed)|
| `GET`  | `/emulator/otp/:login_id`   | Get pending OTP code for a login ID      |
| `POST` | `/emulator/tenant`          | Create a tenant directly (escape hatch)  |
| `GET`  | `/emulator/otps`            | List all pending OTP codes (userId→code) |
| `GET`  | `/emulator/snapshot`        | Export full emulator state as JSON       |
| `POST` | `/emulator/snapshot`        | Import / restore a previously exported state |
| `GET`  | `/.well-known/jwks.json`    | JWKS for JWT verification                |
| `GET`  | `/v2/keys/:project_id`      | JWKS (alternate path used by some SDKs)  |

### Auth — Password

| Method | Path                         | Description                              |
| ------ | ---------------------------- | ---------------------------------------- |
| `POST` | `/v1/auth/password/signup`   | Sign up with email + password            |
| `POST` | `/v1/auth/password/signin`   | Sign in with email + password            |
| `POST` | `/v1/auth/password/replace`  | Replace password (requires old password) |
| `POST` | `/v1/auth/password/reset`    | Initiate password reset (returns token)  |
| `POST` | `/v1/auth/password/update`   | Complete password reset with token       |
| `GET`  | `/v1/auth/password/policy`   | Get password policy configuration        |

### Auth — Magic Link

| Method | Path                                  | Description                                      |
| ------ | ------------------------------------- | ------------------------------------------------ |
| `POST` | `/v1/auth/magiclink/signup/email`     | Sign up via magic link (email)                   |
| `POST` | `/v1/auth/magiclink/signin/email`     | Sign in via magic link (email)                   |
| `POST` | `/v1/auth/magiclink/signup-in/email`  | Sign up or sign in via magic link (email)        |
| `POST` | `/v1/auth/magiclink/signup/sms`       | Sign up via magic link (SMS)                     |
| `POST` | `/v1/auth/magiclink/signin/sms`       | Sign in via magic link (SMS)                     |
| `POST` | `/v1/auth/magiclink/signup-in/sms`    | Sign up or sign in via magic link (SMS)          |
| `POST` | `/v1/auth/magiclink/verify`           | Verify magic link token → session                |
| `POST` | `/v1/auth/magiclink/update/email`     | Update email via magic link                      |
| `POST` | `/v1/auth/magiclink/update/phone/sms` | Update phone number via magic link (SMS)         |

### Auth — OTP

| Method | Path                              | Description                               |
| ------ | --------------------------------- | ----------------------------------------- |
| `POST` | `/v1/auth/otp/signup/email`       | Sign up via OTP (email)                   |
| `POST` | `/v1/auth/otp/signin/email`       | Sign in via OTP (email)                   |
| `POST` | `/v1/auth/otp/signup-in/email`    | Sign up or sign in via OTP (email)        |
| `POST` | `/v1/auth/otp/verify/email`       | Verify OTP → session (email)              |
| `POST` | `/v1/auth/otp/signup/phone/sms`   | Sign up via OTP (SMS)                     |
| `POST` | `/v1/auth/otp/signin/phone/sms`   | Sign in via OTP (SMS)                     |
| `POST` | `/v1/auth/otp/signup-in/sms`      | Sign up or sign in via OTP (SMS)          |
| `POST` | `/v1/auth/otp/verify/phone/sms`   | Verify OTP → session (SMS)                |
| `POST` | `/v1/auth/otp/update/phone/sms`   | Update phone number via OTP               |

### Auth — SAML / SSO

| Method | Path                       | Description                             |
| ------ | -------------------------- | --------------------------------------- |
| `POST` | `/v1/auth/saml/start`      | Start SAML flow (returns `?code=…` URL) |
| `POST` | `/v1/auth/saml/authorize`  | Alias for saml/start                    |
| `POST` | `/v1/auth/saml/exchange`   | Exchange SAML code → session            |
| `POST` | `/v1/auth/sso/authorize`   | Alias for saml/start (SSO path)         |
| `POST` | `/v1/auth/sso/exchange`    | Alias for saml/exchange (SSO path)      |

### Session

| Method | Path                        | Description                              |
| ------ | --------------------------- | ---------------------------------------- |
| `POST` | `/v1/auth/refresh`          | Refresh session using refresh JWT        |
| `POST` | `/v1/auth/logout`           | Revoke refresh JWT (current session)     |
| `POST` | `/v1/auth/logoutall`        | Revoke all refresh JWTs for the user     |
| `GET`  | `/v1/auth/me`               | Get user profile (Bearer or DSR cookie)  |
| `GET`  | `/v1/auth/me/history`       | Get login history for the current user   |
| `POST` | `/v1/auth/validate`         | Validate session JWT → decoded claims    |
| `POST` | `/v1/auth/tenant/select`    | Select active tenant for the session     |

### Management — User

| Method   | Path                                    | Description                                          |
| -------- | --------------------------------------- | ---------------------------------------------------- |
| `POST`   | `/v1/mgmt/user/create`                  | Create a user                                        |
| `POST`   | `/v1/mgmt/user/create/test`             | Create a test user (included in delete-all)          |
| `POST`   | `/v1/mgmt/user/create/batch`            | Create multiple users in one request                 |
| `GET`    | `/v1/mgmt/user?loginid=…`              | Load user by loginId                                 |
| `DELETE` | `/v1/mgmt/user?loginid=…`              | Delete user by loginId                               |
| `POST`   | `/v1/mgmt/user/delete`                  | Delete user by loginId (SDK POST variant)            |
| `GET`    | `/v1/mgmt/user/userid?userid=…`        | Load user by userId                                  |
| `DELETE` | `/v1/mgmt/user/userid?userid=…`        | Delete user by userId                                |
| `POST`   | `/v1/mgmt/user/delete/batch`            | Delete multiple users in one request                 |
| `DELETE` | `/v1/mgmt/user/test/delete/all`         | Delete all test users                                |
| `POST`   | `/v1/mgmt/user/search`                  | Search users (filters, pagination)                   |
| `POST`   | `/v2/mgmt/user/search`                  | Search users (Node SDK alias)                        |
| `POST`   | `/v1/mgmt/user/update`                  | Full replace of user fields                          |
| `PATCH`  | `/v1/mgmt/user/patch`                   | Partial update (preserves unspecified fields)        |
| `POST`   | `/v1/mgmt/user/update/email`            | Update email + verified flag                         |
| `POST`   | `/v1/mgmt/user/update/name`             | Update display name                                  |
| `POST`   | `/v1/mgmt/user/update/phone`            | Update phone number                                  |
| `POST`   | `/v1/mgmt/user/update/loginid`          | Update loginId                                       |
| `POST`   | `/v1/mgmt/user/update/role/set`         | Set roles on a user                                  |
| `POST`   | `/v1/mgmt/user/update/role/remove`      | Remove roles from a user                             |
| `POST`   | `/v1/mgmt/user/status`                  | Update user enabled/disabled status                  |
| `POST`   | `/v1/mgmt/user/update/status`           | Alias for status update                              |
| `POST`   | `/v1/mgmt/user/tenant/add`              | Add tenant membership to a user                      |
| `POST`   | `/v1/mgmt/user/tenant/remove`           | Remove tenant membership from a user                 |
| `POST`   | `/v1/mgmt/user/tenant/setRole`          | Set tenant-scoped roles for a user                   |
| `POST`   | `/v1/mgmt/user/logout`                  | Force-logout a user (revoke all sessions)            |
| `POST`   | `/v1/mgmt/user/password/set/active`     | Set active password for a user                       |
| `POST`   | `/v1/mgmt/user/password/set/temporary`  | Set a temporary password (expires on next login)     |
| `POST`   | `/v1/mgmt/user/password/expire`         | Expire a user's password                             |
| `POST`   | `/v1/mgmt/user/embeddedlink`            | Generate an embedded link token                      |
| `POST`   | `/v1/mgmt/user/signin/embeddedlink`     | Alias for embedded link (Node SDK path)              |

### Management — Tests

| Method | Path                                    | Description                                       |
| ------ | --------------------------------------- | ------------------------------------------------- |
| `POST` | `/v1/mgmt/tests/generate/magiclink`     | Generate a magic link token for a test user       |
| `POST` | `/v1/mgmt/tests/generate/otp`           | Generate an OTP code for a test user              |
| `POST` | `/v1/mgmt/tests/generate/enchantedlink` | Generate an enchanted link token for a test user  |

### Management — Tenant

| Method   | Path                      | Description                                  |
| -------- | ------------------------- | -------------------------------------------- |
| `GET`    | `/v1/mgmt/tenant/all`     | List all tenants                             |
| `POST`   | `/v1/mgmt/tenant/create`  | Create a tenant                              |
| `POST`   | `/v1/mgmt/tenant/update`  | Update tenant name / domains                 |
| `GET`    | `/v1/mgmt/tenant?id=…`   | Load tenant by ID                            |
| `DELETE` | `/v1/mgmt/tenant?id=…`   | Delete tenant by ID                          |
| `POST`   | `/v1/mgmt/tenant/delete`  | Delete tenant by ID (Node SDK POST variant)  |
| `POST`   | `/v1/mgmt/tenant/search`  | Search tenants                               |

### Management — Permissions

| Method | Path                              | Description           |
| ------ | --------------------------------- | --------------------- |
| `POST` | `/v1/mgmt/authz/permission`       | Create a permission   |
| `GET`  | `/v1/mgmt/authz/permission/all`   | List all permissions  |
| `POST` | `/v1/mgmt/authz/permission/update`| Update a permission   |
| `POST` | `/v1/mgmt/authz/permission/delete`| Delete a permission   |

### Management — Roles

| Method | Path                         | Description      |
| ------ | ---------------------------- | ---------------- |
| `POST` | `/v1/mgmt/authz/role`        | Create a role    |
| `GET`  | `/v1/mgmt/authz/role/all`    | List all roles   |
| `POST` | `/v1/mgmt/authz/role/update` | Update a role    |
| `POST` | `/v1/mgmt/authz/role/delete` | Delete a role    |

### Management — Access Keys

| Method | Path                          | Description                         |
| ------ | ----------------------------- | ----------------------------------- |
| `POST` | `/v1/mgmt/accesskey`          | Create an access key                |
| `GET`  | `/v1/mgmt/accesskey/all`      | List all access keys                |
| `POST` | `/v1/mgmt/accesskey/update`   | Update access key name or expiry    |
| `POST` | `/v1/mgmt/accesskey/delete`   | Delete an access key                |
| `POST` | `/v1/mgmt/accesskey/disable`  | Disable an access key               |

### Management — Auth Method Config

| Method | Path                            | Description                               |
| ------ | ------------------------------- | ----------------------------------------- |
| `GET`  | `/v1/mgmt/config/auth-methods`  | Get enabled/disabled state of all methods |
| `PUT`  | `/v1/mgmt/config/auth-methods`  | Update enabled/disabled state             |

### Management — JWT

| Method | Path                           | Description                        |
| ------ | ------------------------------ | ---------------------------------- |
| `POST` | `/v1/mgmt/jwt/update`          | Update custom claims on a JWT      |
| `POST` | `/v1/mgmt/jwt/template`        | Create a JWT template              |
| `GET`  | `/v1/mgmt/jwt/template/all`    | List all JWT templates             |
| `POST` | `/v1/mgmt/jwt/template/update` | Update a JWT template              |
| `POST` | `/v1/mgmt/jwt/template/delete` | Delete a JWT template              |
| `POST` | `/v1/mgmt/jwt/template/set-active` | Set the active JWT template    |
| `GET`  | `/v1/mgmt/jwt/template/active` | Get the currently active template  |

### Management — Connectors

| Method | Path                        | Description          |
| ------ | --------------------------- | -------------------- |
| `POST` | `/v1/mgmt/connector`        | Create a connector   |
| `GET`  | `/v1/mgmt/connector/all`    | List all connectors  |
| `POST` | `/v1/mgmt/connector/update` | Update a connector   |
| `POST` | `/v1/mgmt/connector/delete` | Delete a connector   |

### Management — Custom Attributes

| Method | Path                           | Description              |
| ------ | ------------------------------ | ------------------------ |
| `POST` | `/v1/mgmt/user/attribute`      | Create a custom attribute|
| `GET`  | `/v1/mgmt/user/attribute/all`  | List all custom attributes|
| `POST` | `/v1/mgmt/user/attribute/delete`| Delete a custom attribute|

### Management — Identity Providers

| Method | Path                   | Description                         |
| ------ | ---------------------- | ----------------------------------- |
| `POST` | `/v1/mgmt/idp`         | Create an identity provider         |
| `GET`  | `/v1/mgmt/idp/all`     | List all identity providers         |
| `POST` | `/v1/mgmt/idp/update`  | Update an identity provider         |
| `POST` | `/v1/mgmt/idp/delete`  | Delete an identity provider         |

### Emulator — IdP OIDC

| Method | Path                                                        | Description                              |
| ------ | ----------------------------------------------------------- | ---------------------------------------- |
| `GET`  | `/emulator/idp/:idp_id/.well-known/openid-configuration`    | OIDC discovery document                  |
| `GET`  | `/emulator/idp/:idp_id/jwks`                                | IdP public key (JWKS)                    |
| `GET`  | `/emulator/idp/:idp_id/authorize`                           | OIDC authorize (user picker or `login_id` param) |
| `POST` | `/emulator/idp/:idp_id/token`                               | Exchange authorization code → tokens     |
| `GET`  | `/emulator/idp/callback`                                    | SP callback (code → SP code → redirect)  |

### Emulator — IdP SAML

| Method | Path                                  | Description                                |
| ------ | ------------------------------------- | ------------------------------------------ |
| `GET`  | `/emulator/idp/:idp_id/metadata`      | SAML EntityDescriptor XML                  |
| `GET`  | `/emulator/idp/:idp_id/sso`           | SAML SSO (user picker or `login_id` param) |
| `POST` | `/emulator/idp/saml/acs`              | SP-side ACS callback (SAML → SP code)      |

## Management Auth

Include `Authorization: Bearer <project_id>:<management_key>` on all `/v1/mgmt/…` requests.

```
Authorization: Bearer emulator-project:emulator-key
```

## Running Tests

All commands are run from the **repo root**. Nx handles building dependencies before running tests.

### Overview

| Suite | Command | Needs emulator? | Speed |
|---|---|---|---|
| Rust unit | `npm run test:unit` | No | ~5s |
| API integration | `npm run test:api` | No (starts it) | ~30s |
| SDK integration | `npm run test:sdk-js` / `test:sdk-nodejs` | No (starts it) | ~30s |
| E2E (Playwright) | `npm run test:e2e` | No (starts it) | ~2m |

---

### Rust Unit Tests

```bash
npm run test:unit
# equivalent: nx run api:test
```

---

### API & SDK Integration Tests

Vitest suites that auto-start the emulator via `cargo build`.

```bash
npm run test:api
npm run test:sdk-js
npm run test:sdk-nodejs
```

> The emulator runs on port **4501** during integration tests. Do not have another process on that port.

Run unit + API integration + E2E in one shot:

```bash
npm run test
```

---

### E2E Tests (Playwright)

Playwright builds the UI, starts the emulator on port **4500**, runs all tests headless, then shuts everything down.

#### One-time setup

```bash
cd apps/ui && npx playwright install chromium
```

#### Run

```bash
npm run test:e2e
# equivalent: nx run ui:test
```

#### Headed mode (see the browser)

```bash
npm run test:e2e:watch
```

#### Filter to specific tests

```bash
npm run test:e2e -- --grep "Users"
npm run test:e2e:watch -- --grep "create user"
```

#### Troubleshooting

If you see `Address already in use` on port 4500:

```bash
lsof -ti:4500 | xargs kill -9
```

---

### Coverage

```bash
npm run api:coverage          # text summary
npm run api:coverage:html     # open HTML report
```

Requires `cargo-llvm-cov`:

```bash
cargo install cargo-llvm-cov
```

---

### Parity Tests (compare against live Descope)

```bash
export DESCOPE_PARITY_PROJECT_ID=Pxxx
export DESCOPE_PARITY_MANAGEMENT_KEY=your-key
make test-parity
```

## SDK Integration Examples

### Node.js (`@descope/node-sdk`)

```typescript
import DescopeClient from "@descope/node-sdk";

const sdk = DescopeClient({
  projectId: "emulator-project",
  baseUrl: "http://localhost:4500",
});

// Signs up, returns session + refresh JWTs
const { data } = await sdk.password.signUp("alice@example.com", "Secret123!");
console.log(data.sessionJwt);

// Validate session (uses emulator's JWKS)
const valid = await sdk.validateSession(data.sessionJwt);
```

### Python (`descope-python-sdk`)

```python
from descope import DescopeClient

client = DescopeClient(
    project_id="emulator-project",
    base_url="http://localhost:4500"
)

res = client.password.sign_up("alice@example.com", "Secret123!")
print(res["data"]["sessionJwt"])
```

### Go (`descope-go-sdk`)

```go
import "github.com/descope/go-sdk/descope/api"

client, _ := api.NewDescopeClient(api.Config{
    ProjectID: "emulator-project",
    BaseURL:   "http://localhost:4500",
})
```

### curl

```bash
# Sign up with password
curl -s http://localhost:4500/v1/auth/password/signup \
  -H 'Content-Type: application/json' \
  -d '{"loginId": "alice@example.com", "password": "Secret123!"}' | jq

# Search users (management API)
curl -s http://localhost:4500/v1/mgmt/user/search \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer emulator-project:emulator-key' \
  -d '{}' | jq
```

The JWKS endpoint (`/.well-known/jwks.json`) serves the emulator's public key, so `validateSession()` works against tokens issued by the emulator.

## Emulator Deviations

Rescope intentionally deviates from real Descope in several areas to simplify local development:

| Behavior | Descope (Production) | Rescope (Emulator) |
|---|---|---|
| **OTP delivery** | Sends real email/SMS | Returns code directly in API response (`"code": "123456"`) |
| **Magic link delivery** | Sends email/SMS with link | Returns token directly in API response (`"token": "..."`) |
| **Password reset** | Sends email with reset link | Returns token directly in API response (`"token": "..."`) |
| **Management auth** | Required (`401` without valid key) | Optional (requests without credentials succeed; invalid credentials return `401`) |
| **Data persistence** | Cloud database | In-memory (lost on restart; use snapshots/seed for persistence) |
| **Rate limiting** | Enforced | None |
| **Email/phone verification** | Real verification flow | Automatic on OTP verify; manual via management API |
| **Webhook delivery** | Real HTTP webhooks | Logged to console (or invoked if connector mode is `invoke`) |
| **SSO / Identity Providers** | Integrates with real IdPs (Okta, Azure AD, etc.) | Emulates IdPs locally — built-in OIDC + SAML endpoints with user picker UI |

