# Hybrid Data Residency — Google Secret Manager secrets

Secretos que hay que crear en **Google Secret Manager (GSM)** para desplegar los
tres componentes del subsistema de residencia (`DataCore`, `DataBridge`,
`DataAgent`).

Convención (igual que TrustGuard/TrustGate): **un secret por app y por proyecto**
—`neuraltrust-app-dev` y `neuraltrust-app-prod`— que contiene los pares
`KEY=VALUE`. En Kubernetes se materializa como el Secret nativo que referencian
los deployments (`*-secrets`) vía external-secrets / sealed-secrets.

> Esto es **aparte** de los secrets de GitHub Actions (`DEV/PROD_WIF_PROVIDER`,
> `DEV/PROD_WIF_SERVICE_ACCOUNT`, `GH_TOKEN`, `SLACK_WEBHOOK_URL`,
> `OPENAI_API_KEY`), que viven en GitHub, no en GSM.

---

## DataCore — secret `datacore` → Secret `datacore-secrets`

| Clave | Propósito | dev | prod |
|---|---|:---:|:---:|
| `AUTH_JWT_HS256_SECRET` | Firma/verificación JWT del API REST | ✅ | ✅ |
| `CLICKHOUSE_USER` | Usuario ClickHouse (backend `saas`) | ✅ | ✅ |
| `CLICKHOUSE_PASSWORD` | Password ClickHouse | ✅ | ✅ |

Dev y prod usan `RESIDENCY_ALLOW_STUB=false` (ClickHouse real), así que **ambos**
requieren las tres claves. En dev el ClickHouse es **ClickHouse Cloud**
(`jxkec3c1gs.europe-west4.p.gcp.clickhouse.cloud:9440`, protocolo nativo + TLS;
el `8443` es el interfaz HTTPS que el driver de Go no usa).

---

## DataBridge — secret `databridge` → Secret `databridge-secrets`

| Clave / material | Propósito | dev | prod |
|---|---|:---:|:---:|
| `SOUTHBOUND_TLS_CERT_FILE` (cert servidor) | mTLS southbound (los agentes entran) | cert-manager | ✅ |
| `SOUTHBOUND_TLS_KEY_FILE` (**clave privada**) | mTLS southbound | cert-manager | ✅ |
| `SOUTHBOUND_CLIENT_CA_FILE` (CA de clientes) | Verifica los certs de DataAgent | cert-manager | ✅ |

**Dev ya corre mTLS real** (réplica de prod), pero el material TLS **no va en GSM**:
lo emite **cert-manager** con una CA privada autofirmada (`residency-ca-dev`, ver
`DataBridge/k8s/dev-pki`). El cert de servidor sale en el Secret
`databridge-southbound-tls` (`tls.crt`/`tls.key`/`ca.crt`), montado como volumen;
la misma `ca.crt` actúa de CA de clientes. Por tanto en dev **no hay que crear
ningún secret en GSM** para DataBridge. `AUTH_MODE` no es secreto.

En prod el material mTLS depende de **RUN-829** (emisión de certs con una CA/PKI
de producción) y son ficheros (cert/clave/CA): lo habitual es un Secret
`kubernetes.io/tls` montado como volumen, no pares `KEY=VALUE`.

> `cert-manager` = emitido por cert-manager en el cluster, no en GSM.

---

## DataAgent — secret `dataagent` → Secret `dataagent-secrets`

| Clave / material | Propósito | dev | prod |
|---|---|:---:|:---:|
| `ENROLMENT_TOKEN` | Token de enrolamiento en el primer dial a DataBridge | ✅ | ✅ |
| `DATABASE_URL` | DSN read-only del store del cliente (solo si `STORE_BACKEND=postgres`) | ⬜ | ✅ |
| `TLS_CLIENT_CERT_FILE` (cert cliente) | mTLS cliente hacia DataBridge | cert-manager | ✅ |
| `TLS_CLIENT_KEY_FILE` (**clave privada**) | mTLS cliente | cert-manager | ✅ |
| `TLS_CA_FILE` (CA de DataBridge) | Pin de la CA del servidor | cert-manager | ✅ |

**Dev ya corre mTLS real.** El material TLS lo emite **cert-manager** (Secret
`dataagent-client-tls`, firmado por la misma CA `residency-ca-dev`), montado como
volumen — **no va en GSM**. Lo único que hay que poner en el Secret
`dataagent-secrets` en dev es `ENROLMENT_TOKEN` (el pod lo consume vía
`envFrom.secretRef`, así que el Secret debe existir). Dev sigue con
`STORE_BACKEND=memory`, así que **no** necesita `DATABASE_URL`.
`RESIDENCY_REGISTRY_FILE` es una ruta (config), no un secreto.

> **Frontera de confianza:** DataAgent corre en el entorno del **cliente**. En
> producción real estos secretos viven en el GSM / almacén del cliente (o se
> inyectan vía el chart `neuraltrust-platform`), no necesariamente en
> `neuraltrust-app-prod`.

---

## Qué crear ya

| Entorno | Proyecto | Secrets necesarios |
|---|---|---|
| dev | `neuraltrust-app-dev` | `datacore` (`AUTH_JWT_HS256_SECRET` + `CLICKHOUSE_USER` + `CLICKHOUSE_PASSWORD`) · `dataagent` (`ENROLMENT_TOKEN`) |
| prod | `neuraltrust-app-prod` | `datacore` (JWT + ClickHouse), `databridge` (mTLS servidor, tras RUN-829), `dataagent` (enrolment + DSN + mTLS cliente, normalmente en el lado cliente) |

> **mTLS en dev:** el material TLS (DataBridge servidor + DataAgent cliente) lo
> emite **cert-manager** con la CA privada `residency-ca-dev`, no GSM. Aplicar una
> vez por cluster el bootstrap de la CA: `DataBridge/k8s/dev-pki` (ClusterIssuer
> autofirmado → CA → ClusterIssuer `residency-ca-dev`). Los leaf certs viven en los
> overlays dev de cada app y referencian ese ClusterIssuer.

### Ejemplo de creación (blob `KEY=VALUE`)

```bash
printf 'AUTH_JWT_HS256_SECRET=...\nCLICKHOUSE_USER=...\nCLICKHOUSE_PASSWORD=...\n' \
  | gcloud secrets create datacore \
      --project=neuraltrust-app-prod \
      --data-file=-

# Rotación / nueva versión
printf 'AUTH_JWT_HS256_SECRET=...\n...' \
  | gcloud secrets versions add datacore \
      --project=neuraltrust-app-prod \
      --data-file=-
```

### Ejemplo material mTLS (ficheros, tipo TLS)

En **dev** no se crea a mano: cert-manager emite los Secrets a partir de la CA
privada. Basta con aplicar el bootstrap una vez y desplegar los overlays:

```bash
# Una vez por cluster dev (ClusterIssuers + CA en el ns cert-manager)
kubectl apply -k DataBridge/k8s/dev-pki
# Los leaf certs (databridge-southbound-tls, dataagent-client-tls) los crean
# los overlays dev de cada app al desplegarse.
```

En **prod** (o para material emitido fuera del cluster, RUN-829):

```bash
kubectl create secret tls databridge-southbound-tls \
  --cert=southbound.crt --key=southbound.key -n databridge
# CA de clientes por separado (montada como fichero)
```

---

## Referencias

- Diseño del subsistema: `TrustGate/docs/hybrid-control-plane-agent.md`
- Claves por repo documentadas en cada `k8s/base/secrets.env.example`
- Patrón de referencia (CSI + `.env` blob): `TrustGuard/k8s`, `TrustGate/k8s`
