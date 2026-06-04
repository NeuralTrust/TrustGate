# AgentGateway Dashboard

Admin dashboard for AgentGateway: manage registries, consumers, auth credentials and policies per gateway.

Built with Next.js 16 (App Router), TypeScript, Tailwind CSS v4, Radix UI and TanStack Query.

## Architecture

The dashboard never talks to the admin API from the browser. Instead it uses a
**Backend-For-Frontend (BFF)** pattern:

```
Browser ──▶ /api/admin/*  (Next.js route handler)
                │  mints an HS256 JWT signed with SERVER_SECRET_KEY
                ▼
          AgentGateway admin API  (Authorization: Bearer <jwt>)
```

- `src/lib/jwt.ts` — signs short-lived admin tokens with `jose`.
- `src/app/api/admin/[...path]/route.ts` — proxies every request to the admin API.
- The active gateway is stored in the `ag_active_gateway` cookie and switched from the top-right selector.

## Environment

Copy `.env.example` to `.env.local` for local development:

| Variable            | Required | Description                                                                 |
| ------------------- | -------- | --------------------------------------------------------------------------- |
| `SERVER_SECRET_KEY` | yes      | HS256 secret used to sign admin JWTs. **Must match the admin server's key.** |
| `ADMIN_API_URL`     | no       | Admin API base URL. Defaults to `http://localhost:8080`.                    |
| `ADMIN_TEAM_ID`     | no       | Optional `team_id` claim forwarded to the admin API.                        |
| `ADMIN_USER_ID`     | no       | Optional `user_id` claim forwarded to the admin API.                        |

## Local development

```bash
cd frontend
npm install
npm run dev        # http://localhost:3000
```

Requires the admin API running on `ADMIN_API_URL` (default `http://localhost:8080`).

## Docker Compose

The dashboard ships as an overlay on top of the main compose files. From the repo root:

```bash
docker compose \
  -f docker-compose.yaml \
  -f docker-compose.api.yaml \
  -f docker-compose.frontend.yaml \
  up -d --build
```

The dashboard is served on [http://localhost:3000](http://localhost:3000) and reaches the
admin service at `http://admin:8080` over the compose network. `SERVER_SECRET_KEY` is read from
the root `.env` file, the same one used by the gateway servers.
