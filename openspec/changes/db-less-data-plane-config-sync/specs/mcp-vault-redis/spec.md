# Delta for MCP Vault on Redis (DB-less MCP plane)

This change moves the MCP per-user OAuth credential store (vault) from Postgres to
Redis on the DB-less MCP plane. Vault is runtime-mutable per-user state, not
config, so it cannot live in the compiled snapshot. A Redis-backed
`vaultdomain.Repository` stores the already-encrypted credential blob and satisfies
the same interface used by the MCP credential-exchange path. A missing entry
degrades gracefully to a re-consent. Maps to ENG-950 QA: "MCP per-user OAuth
credentials resolve via the Redis-backed vault repo; missing entry degrades to
re-consent".

## ADDED Requirements

### Requirement: Redis-backed vault repository

On the DB-less MCP plane the vault MUST be backed by Redis, keyed by gateway id,
principal subject, and provider. It MUST support upsert, find, list-by-principal,
and delete, storing the credential value already encrypted by the existing
encrypter (values MUST NOT be stored in plaintext). It MUST require no Postgres.

#### Scenario: Upsert then find
- GIVEN the DB-less MCP plane with the Redis-backed vault
- WHEN a credential is upserted for a gateway/principal/provider and later found
- THEN the stored encrypted value MUST be returned for that key

#### Scenario: Value stored encrypted
- GIVEN a credential upserted through the Redis-backed vault
- WHEN the raw Redis value is inspected
- THEN it MUST be the encrypted blob, never plaintext credentials

### Requirement: Credential exchange works DB-less

The MCP credential-exchange (forwarded) path MUST resolve per-user credentials
through the Redis-backed vault with no Postgres access, and credential refresh
MUST persist updated tokens back to Redis.

#### Scenario: Forwarded resolution uses Redis vault
- GIVEN a principal with a stored credential on the DB-less MCP plane
- WHEN the credential-exchange path resolves the credential
- THEN it MUST be served from Redis without any database access

### Requirement: Missing credential degrades to re-consent

When no credential exists for the requested key, the Redis-backed vault MUST
return the not-found signal the credential path already handles as "re-consent",
so a lost or absent entry results in a normal consent prompt, not an outage.

#### Scenario: Absent entry prompts re-consent
- GIVEN no stored credential for a gateway/principal/provider
- WHEN the credential-exchange path looks it up
- THEN the vault MUST return `vaultdomain.ErrNotFound` and the flow MUST proceed to re-consent
