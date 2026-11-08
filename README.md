# NestJS RBAC API Starter

A production-ready NestJS starter with server-side role-based access control: JWT authentication
with rotating refresh tokens, dynamic roles and permissions, per-user ALLOW/DENY overrides,
append-only security auditing, OpenAPI docs derived from the same Zod schemas the API enforces,
and first-class support for **both PostgreSQL and MySQL** — all built test-first (246 tests).

## Features

- **Auth vertical** — login, refresh (rotation + family reuse detection), logout, logout-all,
  forgot/reset password (pluggable mailer port), change password, `/auth/me`.
  Argon2id password hashing, httpOnly-cookie refresh tokens (hashed at rest),
  5-failure / 15-minute lockout, per-route throttling.
- **RBAC** — dynamic `resource.action` permission catalogue, role CRUD, per-user
  ALLOW/DENY/INHERIT overrides (DENY always wins), protected system Super Admin role.
- **Deny by default** — a bootstrap scan fails startup if any route lacks
  `@Public()`, `@AuthenticatedOnly()` or `@RequirePermissions()`.
- **Audit trail** — security events (login, lockout, token reuse, RBAC mutations…) redacted at
  write time, exposed through an append-only API.
- **Docs that cannot drift** — `@RequirePermissions` doubles as the OpenAPI annotation and
  request bodies are generated from the exact Zod schemas the validation pipes enforce.
- **Dual dialect** — separate Prisma schemas and migration trees for PostgreSQL and MySQL,
  verified by CI on both.

## Tech stack

| Concern    | Choice                                                                           |
| ---------- | -------------------------------------------------------------------------------- |
| Framework  | NestJS 12, strict TypeScript, Node ≥ 22, ESM                                     |
| ORM        | Prisma 7 with driver adapters (`@prisma/adapter-pg` / `@prisma/adapter-mariadb`) |
| Validation | Zod 4 (pipes, env, OpenAPI)                                                      |
| Auth       | `@nestjs/jwt` (access) + Argon2id (`@node-rs/argon2`)                            |
| Docs       | `@nestjs/swagger`                                                                |
| Tests      | Vitest (unit / integration / e2e against a real DB)                              |
| Tooling    | pnpm, ESLint (type-aware), Prettier, GitHub Actions                              |

## Quickstart (development)

```bash
# 1. Install
pnpm install

# 2. Databases (reads POSTGRES_PASSWORD / MYSQL_* from .env)
cp .env.example .env        # then fill in real values
docker compose up -d postgres

# 3. Secrets — generate a strong JWT secret
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
# put it (plus SUPER_ADMIN_PASSWORD) into .env

# 4. Schema + catalogue seed (idempotent Super Admin bootstrap)
pnpm db:migrate
pnpm db:seed

# 5. Run
pnpm start:dev
```

Open `http://localhost:3000/api/docs`, log in as the super admin, and call any endpoint.

## Commands

| Command                                               | Purpose                                                   |
| ----------------------------------------------------- | --------------------------------------------------------- |
| `pnpm build` / `pnpm start`                           | Compile / run `dist/main.js`                              |
| `pnpm test`                                           | Unit tests (no DB needed)                                 |
| `pnpm test:integration`                               | Service-level tests against `TEST_DATABASE_URL`           |
| `pnpm test:e2e`                                       | Full HTTP lifecycle tests against `TEST_DATABASE_URL`     |
| `pnpm test:all` / `pnpm test:cov`                     | Every project / with coverage                             |
| `pnpm typecheck` / `pnpm lint` / `pnpm format`        | tsc, ESLint, Prettier                                     |
| `pnpm db:migrate` / `pnpm db:deploy` / `pnpm db:seed` | Migrate dev DB / apply committed migrations / seed        |
| `pnpm db:deploy:test`                                 | Apply migrations to the test database                     |
| `pnpm db:use:postgres` / `pnpm db:use:mysql`          | Switch active dialect (schema + migrations path)          |
| `pnpm db:parity`                                      | Fail if the two Prisma schemas drift apart                |
| `pnpm prisma:generate`                                | Regenerate the client for the current `DATABASE_PROVIDER` |

## Configuration

All configuration comes from environment variables, validated at boot by
`src/config/env.validation.ts` — an invalid environment fails startup with a readable list of
issues. Copy `.env.example` and fill it in; `.env` is git-ignored and must never be committed.

| Variable                                            | Default       | Notes                                                                |
| --------------------------------------------------- | ------------- | -------------------------------------------------------------------- |
| `NODE_ENV`                                          | `development` | `production` enables extra safety checks below                       |
| `PORT`                                              | `3000`        |                                                                      |
| `DATABASE_PROVIDER`                                 | —             | `postgresql` or `mysql` (selects schema + migrations dir)            |
| `DATABASE_URL` / `TEST_DATABASE_URL`                | —             | Must match the provider scheme; tests use the isolated DB            |
| `JWT_ACCESS_SECRET`                                 | —             | ≥ 32 chars, unique per environment                                   |
| `JWT_ISSUER` / `JWT_AUDIENCE`                       | —             | Pin both; they are validated on every request                        |
| `ACCESS_TOKEN_TTL_SECONDS`                          | `900`         | Keep short — permissions are never in the token                      |
| `REFRESH_TOKEN_TTL_DAYS`                            | `14`          |                                                                      |
| `COOKIE_SECURE`                                     | `false`       | **must be `true` in production** or boot fails                       |
| `DOCS_ENABLED`                                      | `true`        | **must be `false` in production** or boot fails                      |
| `AUTH_THROTTLE_LIMIT` / `AUTH_THROTTLE_TTL_SECONDS` | `10` / `60`   | Auth-route request budget per IP                                     |
| `SUPER_ADMIN_EMAIL` / `SUPER_ADMIN_PASSWORD`        | —             | Bootstrap seed, idempotent; placeholder value rejected in production |

### Secure credential handling (production)

- Never commit `.env`; inject it via your platform's secret manager (Docker secrets, Kubernetes
  Secrets, Vault, SSM…), not baked images or CI logs.
- Generate `JWT_ACCESS_SECRET` per environment (`node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`);
  rotate it by deploying with a new value — access tokens are short-lived, refresh families
  re-establish on next login.
- `SUPER_ADMIN_PASSWORD` is consumed once by the idempotent seed; the seed never resets an
  existing super admin password. Change it later through `POST /api/auth/change-password`.
- Grant the application DB user least privilege. For the audit table, grant **`INSERT` and
  `SELECT` only** — no `UPDATE`/`DELETE` — so the trail is tamper-evident at the database level,
  not merely by API convention.

## Security model

- **Permissions are never in the JWT.** Access tokens carry `sub`/`sid`/`jti` only. Every request
  re-evaluates the user's effective permissions server-side (uncached, by design) so revoking a
  role, setting a DENY override, or disabling an account takes effect immediately.
- **Guard chain** (single ordered list, reused verbatim in tests):
  `ThrottlerGuard → JwtAuthGuard → PermissionsGuard`.
- **Deny by default.** The bootstrap route scan fails startup on any handler without an explicit
  policy decorator, and names every offending route at once.
- **Override semantics.** effective = (role grants ∪ ALLOW) ∖ DENY. `INHERIT` is expressed by
  deleting the override row. Non-admins can never grant the Super Admin role, and grant-scope
  checks require the actor to hold every permission they hand out.
- **Super Admin** is a protected system role: undeletable, unrenamable, always full-access; the
  last holder cannot be removed or demoted by a non-holder.
- **Refresh tokens** are stored only as Argon2id hashes, rotated on every use; reusing a spent
  token revokes the whole family and is audited.
- **Lockout**: 5 consecutive failed logins lock the account for 15 minutes; an admin
  reactivation (`PATCH /api/users/:id { "status": "ACTIVE" }`) clears the counters.
- **Views are whitelisted** (`UserAdminView`, `RoleView`…) — Prisma records never leave the
  service layer, so new columns cannot leak by accident.

## API surface

Global prefix `/api`. Bearer access token required unless noted.

| Routes                                                                                               | Policy                                               |
| ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `POST /auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/forgot-password`, `/auth/reset-password` | `@Public()` (login is throttled + lockout-protected) |
| `POST /auth/logout-all`, `POST /auth/change-password`, `GET /auth/me`                                | any authenticated user                               |
| `GET/POST/PATCH/DELETE /users…`, `PUT /users/:id/roles`                                              | `users.read/create/update/delete/assign-roles`       |
| `/roles…` (incl. `PUT /roles/:id/permissions`)                                                       | `roles.read/create/update/delete`                    |
| `/permissions…`                                                                                      | `permissions.read/create/update/delete`              |
| `GET /permission-overrides/:userId`, `PUT …/:permissionKey`                                          | `permission-overrides.read/manage`                   |
| `GET /audit-logs?limit=&offset=`                                                                     | `audit-logs.read`                                    |

The 17-key catalogue is defined in `src/database/seeds/rbac-catalogue.ts`; seeded roles are
`SUPER_ADMIN` (system), `USER_ADMIN` and `READ_ONLY`.

`GET /auth/me` returns the caller's authorization facts as `{ user, roles, permissions }`:
`roles` lists the assigned role names and `permissions` is the effective set
`(role grants ∪ ALLOW) \ DENY`, recomputed per request. A system-role holder receives the
whole live catalogue, so a client can gate navigation and actions without re-implementing the
evaluation algorithm.

## OpenAPI docs

`/api/docs` (UI) and `/api/docs.json` (raw document) are served only when `DOCS_ENABLED` is
true — and environment validation refuses to boot production with docs enabled, so exposure in
production is a fail-closed mistake rather than a silent default. Public auth routes appear
unsecured in the document; every other operation lists its bearer requirement and the exact
permission keys it needs.

## Dual-database workflow

`DATABASE_PROVIDER` (required env) selects everything, consistently:

- `prisma/schema.postgresql.prisma` + `prisma/migrations/postgresql/`, or
- `prisma/schema.mysql.prisma` + `prisma/migrations/mysql/`,
- and the matching driver adapter inside `PrismaService` at runtime.

The two schemas must stay logically identical — `pnpm db:parity` fails if they drift (it
compares models with `@db.*` dialect attributes normalized). After switching provider, run
`pnpm prisma:generate` before typechecking or tests. CI runs the full suite against **both**
dialects on every push.

Migrations for the non-default dialect are generated offline with
`DATABASE_PROVIDER=mysql pnpm prisma migrate diff …` and committed under that dialect's folder;
add new migrations on both dialects (or regenerate the second from the updated schema) and let
CI prove the pair.

## Testing

TDD is the project's default: RED (failing test) → GREEN (minimal implementation) → REFACTOR.

- `test/unit` — pure logic (env validation, catalogue, password hashing, token service, audit
  redaction, permission evaluation). No Nest, no DB.
- `test/integration` — real Nest app context against the real database in `TEST_DATABASE_URL`;
  includes the deny-by-default route-policy scan.
- `test:e2e` — full HTTP journeys (auth lifecycle, admin flows, OpenAPI contract, and a single
  12-step lifecycle walk). DB-backed suites are never substituted with mocks.

Set `TEST_DATABASE_URL` to an isolated database you can wipe; `pnpm db:deploy:test` migrates it.

## CI

`.github/workflows/ci.yml` runs two jobs on every push/PR:

- **static** — format check, ESLint, `tsc --noEmit`, unit tests.
- **databases** — matrix over PostgreSQL 16 and MySQL 8.4 service containers: generate,
  migrate + seed smoke test, build, then the integration and e2e suites per dialect.

## Production deployment

```bash
docker build --build-arg DATABASE_PROVIDER=postgresql -t rbac-api:latest .
# migrations are a release step, run outside the container:
pnpm db:deploy
docker run -d --env-file .env.production -p 3000:3000 rbac-api:latest
```

The image is Prisma-client-per-dialect: rebuild with the matching `DATABASE_PROVIDER` build
arg (it must equal the runtime env var). `docker compose --profile app up api` demonstrates the
same wiring locally. Required production settings are enforced, not documented-and-prayed-for:
`COOKIE_SECURE=true`, `DOCS_ENABLED=false`, non-placeholder super admin password.
`ConsoleMailer` ships as the password-reset transport placeholder — swap in a real mail adapter
for the `MailerPort` provider before going live.

## Using this as a template

GitHub → **Use this template** → new repository, then:

1. Rename in `package.json` / `Dockerfile` tags / README.
2. Edit `src/database/seeds/rbac-catalogue.ts` to your domain's resources and actions, and add
   the matching migration for both dialects.
3. Build your first feature module: decorate every controller route with an explicit policy
   (`@Public()` / `@AuthenticatedOnly()` / `@RequirePermissions()`), keep controllers thin,
   return whitelisted views, and record security events through `AuditLogService`.
   The deny-by-default scan will refuse to boot anything you forgot.

## Known limitations

- `GET /users` is unbounded (no pagination yet); so is `GET /audit-logs` beyond its `limit` cap.
- No admin-initiated password reset for another user (self-service reset only, by design).
- Audit events are written best-effort after a mutation succeeds — an audit gap on a crash
  between commit and log is possible; add a transactional outbox if you need exactly-once audit.
- Password-reset emails go to the console transport unless you provide a real mailer.

## License

MIT
