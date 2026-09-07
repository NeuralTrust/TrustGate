-- Aggregate-only inventory; provider names, identifiers and credentials stay in the database.
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '10s';

SHOW transaction_read_only;

SELECT type, enabled, count(*) AS auths
FROM auths
GROUP BY type, enabled
ORDER BY type, enabled;

WITH providers AS (
    SELECT type, config,
           COALESCE(config->'oidc', config->'oauth2', '{}'::jsonb) AS provider
    FROM auths
    WHERE type IN ('oidc', 'oauth2')
)
SELECT count(*) AS providers,
       count(*) FILTER (WHERE type = 'oidc') AS legacy_oidc,
       count(*) FILTER (WHERE jsonb_typeof(provider->'public_keys') = 'array'
                         AND provider->'public_keys' <> '[]'::jsonb) AS inline_keys,
       count(*) FILTER (WHERE btrim(COALESCE(provider->>'subject_claim', '')) <> '') AS custom_subject,
       count(*) FILTER (WHERE btrim(COALESCE(provider->>'client_id', '')) = '') AS missing_client_id,
       count(*) FILTER (WHERE config ? 'oidc' AND config ? 'oauth2') AS dual_payload,
       count(*) FILTER (WHERE btrim(COALESCE(provider->>'issuer', '')) = '') AS missing_issuer,
       count(*) FILTER (WHERE provider ? 'audiences'
                         AND jsonb_typeof(provider->'audiences') <> 'array') AS invalid_audiences_shape
FROM providers;

SELECT consumers.type, consumers.routing_mode, count(*) AS legacy_associations
FROM consumer_auth
JOIN auths ON auths.id = consumer_auth.auth_id
JOIN consumers ON consumers.id = consumer_auth.consumer_id
WHERE auths.type = 'oidc'
GROUP BY consumers.type, consumers.routing_mode;

WITH providers AS (
    SELECT id, gateway_id, type, enabled,
           COALESCE(config->'oidc', config->'oauth2', '{}'::jsonb) AS provider
    FROM auths
    WHERE type IN ('oidc', 'oauth2')
), normalized AS (
    SELECT *, CASE WHEN jsonb_typeof(provider->'audiences') = 'array'
                   THEN provider->'audiences' ELSE '[]'::jsonb END AS audiences
    FROM providers
)
SELECT count(*) AS overlapping_pairs,
       count(*) FILTER (WHERE a.enabled AND b.enabled) AS enabled_overlapping_pairs,
       count(*) FILTER (WHERE a.type <> b.type) AS mixed_type_pairs
FROM normalized a
JOIN normalized b ON a.gateway_id = b.gateway_id AND a.id < b.id
                 AND a.provider->>'issuer' = b.provider->>'issuer'
WHERE a.audiences = '[]'::jsonb OR b.audiences = '[]'::jsonb
   OR EXISTS (
       SELECT 1
       FROM jsonb_array_elements_text(a.audiences) aa(value)
       CROSS JOIN jsonb_array_elements_text(b.audiences) bb(value)
       WHERE regexp_replace(aa.value, '^api://', '') = regexp_replace(bb.value, '^api://', '')
   );

ROLLBACK;
