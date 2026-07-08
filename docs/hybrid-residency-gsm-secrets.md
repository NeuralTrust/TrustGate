# Hybrid Data Residency — Google Secret Manager secrets

Secretos que hay que crear en **Google Secret Manager (GSM)** para desplegar los
tres componentes del subsistema de residencia (`DataCore`, `DataBridge`,
`DataAgent`).

Convencion: **un secret por app y por proyecto** —`neuraltrust-app-dev` y
`neuraltrust-app-prod`— que contiene pares `KEY=VALUE`. En Kubernetes se
materializa como el Secret nativo que referencian los deployments (`*-secrets`)
via external-secrets / sealed-secrets.

> Esto es aparte de los secrets de GitHub Actions (`DEV/PROD_WIF_PROVIDER`,
> `DEV/PROD_WIF_SERVICE_ACCOUNT`, `GH_TOKEN`, `SLACK_WEBHOOK_URL`,
> `OPENAI_API_KEY`), que viven en GitHub, no en GSM.

---

## DataCore — secret `datacore` -> Secret `datacore-secrets`

Runtime namespace esperado: `datacore`.

| Env var runtime | Valor esperado | Secret / key | Proposito | dev | prod |
|---|---|---|---|:---:|:---:|
| `AUTH_JWT_HS256_SECRET` | valor secreto | `datacore-secrets` / `AUTH_JWT_HS256_SECRET` | Firma/verificacion JWT del API REST | si | si |
| `CLICKHOUSE_USER` | valor secreto | `datacore-secrets` / `CLICKHOUSE_USER` | Usuario ClickHouse | si | si |
| `CLICKHOUSE_PASSWORD` | valor secreto | `datacore-secrets` / `CLICKHOUSE_PASSWORD` | Password ClickHouse | si | si |

Notas:

- Dev y prod usan `RESIDENCY_ALLOW_STUB=false`, asi que ambos necesitan
  credenciales reales de ClickHouse.
- `AUTH_JWT_ISSUER` y `AUTH_JWT_AUDIENCE` son configuracion no sensible; no
  deben ir en el secret salvo que Infra use un unico mecanismo para inyectar
  config.
- `DATABRIDGE_TLS` es configuracion, no secreto. El cliente northbound
  DataCore -> DataBridge no tiene mTLS propio hoy.

---

## DataBridge — secret `databridge` -> Secret `databridge-secrets`

Runtime namespace esperado: `databridge`.

`DataBridge` expone el endpoint southbound con TLS de servidor. El material TLS
vive como ficheros montados desde el Secret `databridge-southbound-tls`; las env
vars solo apuntan a esas rutas. La autenticacion de DataAgent es por
`ENROLMENT_TOKEN` sobre el canal TLS.

| Env var runtime | Valor esperado | Secret / key | Proposito | dev | prod |
|---|---|---|---|:---:|:---:|
| `ENROLMENT_TOKEN` | valor secreto | `databridge-secrets` / `ENROLMENT_TOKEN` | Token esperado antes de registrar DataAgent | si | si |
| `SOUTHBOUND_TLS_CERT_FILE` | `/etc/southbound-tls/tls.crt` | `databridge-southbound-tls` / `tls.crt` | Certificado servidor para el endpoint southbound | cert-manager | Infra |
| `SOUTHBOUND_TLS_KEY_FILE` | `/etc/southbound-tls/tls.key` | `databridge-southbound-tls` / `tls.key` | Clave privada del servidor southbound | cert-manager | Infra |
| `SOUTHBOUND_CLIENT_CA_FILE` | ruta CA cliente | secret CA / `ca.crt` | Solo compatibilidad mTLS explicita | opcional | opcional |

Notas:

- `AUTH_MODE=token` es el default de despliegue; `AUTH_MODE=dev` queda solo para
  desarrollo local inseguro.
- `ENROLMENT_TOKEN` debe ser el mismo valor que presenta el DataAgent de ese
  tenant y debe ser aleatorio, de al menos 32 caracteres.
- Este modelo asume despliegue aislado 1:1 para tenant/DataAgent. No reutilizar
  un mismo DataBridge como router multi-tenant con un unico token compartido.
- En dev, cert-manager emite el cert de servidor con la CA `residency-ca-dev`; no
  hay que crear un GSM secret para `tls.crt` / `tls.key`.
- En prod, Infra debe proveer el Secret TLS equivalente y el montaje como volumen
  con las mismas rutas.
- `SOUTHBOUND_CLIENT_CA_FILE` queda vacio por defecto. Solo se configura para
  despliegues internos o transicionales que mantengan mTLS cliente.

---

## DataAgent — secret `dataagent` -> Secret `dataagent-secrets`

Runtime namespace esperado: `dataagent`. En produccion real puede correr dentro
del entorno del cliente; en ese caso estos secretos viven en el secret manager
del cliente o en el chart que use el cliente.

`DataAgent` conecta outbound a DataBridge, valida el certificado de servidor con
`DATABRIDGE_SERVER_NAME` y `TLS_CA_FILE` cuando usa CA privada, y presenta
`ENROLMENT_TOKEN` como metadata gRPC solo sobre transporte seguro.

| Env var runtime | Valor dev | Valor prod / cliente | Secret / key | Proposito | dev | prod |
|---|---|---|---|---|:---:|:---:|
| `ENROLMENT_TOKEN` | valor secreto | valor secreto | `dataagent-secrets` / `ENROLMENT_TOKEN` | Token presentado a DataBridge; debe coincidir con el esperado por DataBridge | si | si |
| `DATABASE_URL` | no aplica (`STORE_BACKEND=memory`) | valor secreto | `dataagent-secrets` / `DATABASE_URL` | DSN read-only si `STORE_BACKEND=postgres` | no | si |
| `RESIDENCY_REGISTRY_FILE` | no aplica (`STORE_BACKEND=memory`) | ruta runtime | config o `dataagent-secrets` / `RESIDENCY_REGISTRY_FILE` | Registro usado junto al backend Postgres | no | si, si postgres |
| `TLS_CA_FILE` | `/etc/databridge-ca/ca.crt` | vacio si usa roots del sistema; ruta CA si PKI privada | CA bundle / `ca.crt`, si aplica | CA para validar el servidor DataBridge | cert-manager | si PKI privada |

Notas:

- El modo default es `TLS_MODE=tls` con `ENROLMENT_TOKEN`; no necesita
  certificado ni clave cliente de DataAgent.
- `DATABRIDGE_SERVER_NAME`, `TLS_MODE` y `STORE_BACKEND` son configuracion, no
  secretos.
- `TLS_CA_FILE` es ruta de fichero montado, no valor secreto en si mismo. Vacio
  significa usar roots del sistema; si DataBridge usa una CA privada, montar el
  bundle CA y apuntar esta env var.
- `TLS_CLIENT_CERT_FILE` y `TLS_CLIENT_KEY_FILE` quedan solo para compatibilidad
  mTLS explicita, no para el default.
- En prod con Postgres, provisionar `DATABASE_URL` y `RESIDENCY_REGISTRY_FILE`
  juntos; no arrancar con uno solo.

---

## Que crear ya

| Entorno | Proyecto | Secrets necesarios |
|---|---|---|
| dev | `neuraltrust-app-dev` | `datacore` (`AUTH_JWT_HS256_SECRET`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`) · `databridge` (`ENROLMENT_TOKEN`) · `dataagent` (`ENROLMENT_TOKEN`) |
| prod | `neuraltrust-app-prod` | `datacore` (JWT + ClickHouse), `databridge` (`ENROLMENT_TOKEN` + TLS servidor montado), `dataagent` (`ENROLMENT_TOKEN`; tambien `DATABASE_URL` + `RESIDENCY_REGISTRY_FILE` si postgres) |

> En dev, la PKI TLS la genera cert-manager con la CA privada
> `residency-ca-dev`. DataBridge recibe cert/key de servidor y DataAgent monta
> solo el CA bundle para validar ese servidor.

### Ejemplo de creacion (blob `KEY=VALUE`)

```bash
printf 'AUTH_JWT_HS256_SECRET=...\nCLICKHOUSE_USER=...\nCLICKHOUSE_PASSWORD=...\n' \
  | gcloud secrets create datacore \
      --project=neuraltrust-app-prod \
      --data-file=-

printf 'ENROLMENT_TOKEN=...\n' \
  | gcloud secrets create databridge \
      --project=neuraltrust-app-prod \
      --data-file=-

printf 'ENROLMENT_TOKEN=...\nDATABASE_URL=...\nRESIDENCY_REGISTRY_FILE=...\n' \
  | gcloud secrets create dataagent \
      --project=neuraltrust-app-prod \
      --data-file=-
```

### Ejemplo material TLS servidor

En dev no se crea a mano: cert-manager emite el Secret a partir de la CA privada.
Basta con aplicar el bootstrap una vez y desplegar los overlays:

```bash
kubectl apply -k DataBridge/k8s/dev-pki
```

En prod, si Infra emite el material fuera del cluster:

```bash
kubectl create secret generic databridge-southbound-tls \
  --type=kubernetes.io/tls \
  --from-file=tls.crt=southbound.crt \
  --from-file=tls.key=southbound.key \
  -n databridge
```

Si el certificado de DataBridge usa una CA privada, DataAgent necesita el
`ca.crt` de esa CA montado como bundle y `TLS_CA_FILE` apuntando al fichero.

---

## Rollout notes

- Crear/provisionar `databridge-secrets` y `dataagent-secrets` antes de arrancar
  pods: los `secretRef` fallan cerrado.
- Confirmar antes del deploy el issuer del certificado DataBridge para prod o
  cliente y decidir si DataAgent usara roots publicas del sistema o CA bundle.
- Tras el rollout, borrar o ignorar recursos antiguos de certificado cliente de
  DataAgent (`dataagent-client-tls`) que hayan quedado de la configuracion mTLS
  anterior.

## Referencias

- Diseño del subsistema: `TrustGate/docs/hybrid-control-plane-agent.md`
- Claves por repo documentadas en cada `k8s/base/secrets.env.example`
