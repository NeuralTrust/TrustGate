# Config-sync provisioning & rollout guide

Manual steps to bring the DB-less pull-based config sync online in Kubernetes for
**TrustGate** (`admin` → `proxy`/`mcp`) and **TrustGuard** (`control` → `data`).

All application and k8s manifest wiring is already committed. What remains is
**outside the repo**: secrets in GCP Secret Manager, TLS certificates for prod,
and the deploy ordering. Without these, prod will not boot.

- TrustGate PR: ENG-950 (`feat/eng-950-db-less-data-plane-config-sync`)
- TrustGuard PR: ENG-939 (`educamacho/eng-939-split-trustguard-into-control-and-data-plane`)

## Topology recap

```
TrustGate:  proxy/mcp (data plane) --gRPC config-sync--> admin (control plane, :8083)
TrustGuard: data      (data plane) --gRPC config-sync--> control (control plane, :8082)
```

The control plane compiles a denormalized snapshot and serves it over a gRPC
listener; the data planes converge on it and serve from an in-memory snapshot
(no Postgres), with an encrypted last-known-good (LKG) cache on disk.

| | Control plane | gRPC port | Data plane(s) | Data plane HTTP |
|---|---|---|---|---|
| TrustGate | `admin` | 8083 | `proxy`, `mcp` | 8081 / 8082 |
| TrustGuard | `control` | 8082 | `data` | 8081 |

---

## 1. Shared secrets (dev **and** prod, both repos)

These live inside the existing `.env` blob mounted via CSI (publish a new version
of the existing secret). Single-line values.

```bash
openssl rand -hex 32      # -> CONFIG_SYNC_TOKEN
openssl rand -base64 32   # -> CONFIG_SYNC_LKG_KEY  (decodes to exactly 32 bytes = AES-256)
```

| Repo | GCP secret (.env blob) | Keys to add |
|---|---|---|
| TrustGate | `agentgateway` (dev: `neuraltrust-app-dev`, prod: `neuraltrust-app-prod`) | `CONFIG_SYNC_TOKEN`, `CONFIG_SYNC_LKG_KEY` |
| TrustGuard | `trustguard` (dev and prod) | `CONFIG_SYNC_TOKEN`, `CONFIG_SYNC_LKG_KEY` |

> `CONFIG_SYNC_TOKEN` must be **identical** on the control and data planes of the
> same repo/environment (control validates it, data sends it). Generate one per
> repo and per environment.

---

## 2. TLS certificates (prod only, both repos)

Dev runs plaintext in-cluster (no certs needed). Prod requires a CA + server
certificate whose **SAN includes the service DNS** the data planes dial:

| Repo | SNI / SAN required | gRPC port |
|---|---|---|
| TrustGate | `agentgateway-admin.agentgateway.svc.cluster.local` | 8083 |
| TrustGuard | `trustguard-control.trustguard.svc.cluster.local` | 8082 |

Quickstart with an internal CA (TrustGate example; repeat with the TrustGuard CN
for the other repo):

This is an **internal** cert (validated by the Go client against our own CA, not
by browsers), so it is not bound to the 825-day public-CA limit. We issue it with
a very long validity (~100 years) to avoid rotation ops — X.509 always carries a
`notAfter`, so "no expiry" in practice means a far-future date.

```bash
# 1) CA (~100 years)
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 36500 \
  -subj "/CN=neuraltrust-config-sync-ca" -out ca.crt

# 2) Server cert with SAN = service DNS (~100 years)
SNI=agentgateway-admin.agentgateway.svc.cluster.local
openssl genrsa -out tls.key 2048
openssl req -new -key tls.key -subj "/CN=$SNI" -out tls.csr
printf "subjectAltName=DNS:%s\n" "$SNI" > san.ext
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 36500 -sha256 -extfile san.ext -out tls.crt
```

Upload the three PEM files as **separate** GCP secrets (the CSI
SecretProviderClass already mounts them under `/etc/secrets/config-sync/`):

| Repo | Prod secrets to create |
|---|---|
| TrustGate | `agentgateway-config-sync-tls-cert`, `agentgateway-config-sync-tls-key`, `agentgateway-config-sync-tls-ca` |
| TrustGuard | `trustguard-config-sync-tls-cert`, `trustguard-config-sync-tls-key`, `trustguard-config-sync-tls-ca` |

```bash
gcloud secrets create agentgateway-config-sync-tls-cert --data-file=tls.crt --project neuraltrust-app-prod
gcloud secrets create agentgateway-config-sync-tls-key  --data-file=tls.key --project neuraltrust-app-prod
gcloud secrets create agentgateway-config-sync-tls-ca   --data-file=ca.crt  --project neuraltrust-app-prod
# …and the three trustguard-… equivalents in the TrustGuard project
```

> `cert` = `tls.crt` (server), `key` = `tls.key` (server), `ca` = `ca.crt` (the CA
> that signed the server cert; the data plane verifies against it). Issued with a
> ~100-year validity, so no routine rotation is expected; rotate only on key
> compromise.

---

## 3. ServiceAccount access to the new secrets

The workload ServiceAccount used by the CSI SecretProviderClass needs
`roles/secretmanager.secretAccessor` on the three new prod TLS secrets — grant it
the same way it already has access to the `.env` blob.

---

## 4. Rollout order (critical)

**Control BEFORE data**, in both repos:

1. Deploy the **control plane** first (TrustGuard `control`, TrustGate `admin`).
   Confirm it becomes `Ready` and opens the gRPC listener (8082 / 8083).
2. Then the **data plane** (TrustGuard `data`, TrustGate `proxy` + `mcp`). Its
   `/readyz` stays **503 until it pulls the first snapshot** — expected; do not
   treat it as a failure while it converges.

---

## 5. Post-deploy verification

```bash
# The Service publishes the gRPC port
kubectl -n agentgateway get svc agentgateway-admin -o jsonpath='{.spec.ports[*].port}'   # -> 8080 8083
kubectl -n trustguard   get svc trustguard-control -o jsonpath='{.spec.ports[*].port}'   # -> 8080 8082

# Data plane converges and turns Ready
kubectl -n agentgateway logs deploy/agentgateway-proxy | rg -i "snapshot|converge|ready"
kubectl -n agentgateway get pods -l component=proxy   # READY 1/1

# Real traffic (per environment)
#   TrustGate:  request through the proxy
#   TrustGuard: POST /v1/guard through the data plane
```

If a data plane never turns Ready, check logs for `configsync`. Common causes:
token mismatch, server cert SAN not covering the SNI, or the ServiceAccount
missing access to the secrets.

---

## 6. Notes & rollback

- **TrustGuard prod is a behavior change**: the data plane stops using Postgres
  and serves from the snapshot. Validate in **dev** first. (Bonus: this resolves
  the cache-coherence gap left by `ENABLE_CACHE_PUBSUB=false`, because the DB-less
  data plane invalidates its caches on every snapshot apply.)
- **dev** works without certs (plaintext in-cluster) but still needs
  `CONFIG_SYNC_TOKEN` and `CONFIG_SYNC_LKG_KEY` in the dev `.env` blob.
- **Rollback** (TrustGuard): remove `CONFIG_SYNC_DATA_PLANE_ENABLED` from the
  `trustguard-data` Deployment (or set it to `false`) and redeploy to return to
  the Postgres-backed data plane.
