-- RUN-1621 · Auditoría B: policies acotadas por grupo que alcanzan tráfico por api-key.
--
-- Por qué importa: tras RUN-1621 una api key no lleva grupo, así que la dimensión
-- de principal NO se evalúa para ese caller y la policy SE APLICA. Como los cinco
-- plugins que pueden llevar scope son restrictivos, el efecto es MÁS control, no
-- menos: una llamada por api key que antes pasaba puede empezar a denegarse o a
-- consumir el bucket de rate-limit del grupo. Cambia sin que nadie edite nada.
--
-- Cada fila es una policy que su dueño debería mirar ANTES de desplegar.
-- Cero filas = nada que revisar en este entorno.
--
-- Uso:  psql "$TRUSTGATE_DB_URL" -f run-1621-audit-groups-apikey.sql

WITH scoped AS (
    SELECT id, gateway_id, name, slug, global,
           mcp_scope -> 'groups' AS groups
    FROM policies
    WHERE enabled
      AND mcp_scope ? 'groups'
      AND jsonb_array_length(COALESCE(mcp_scope -> 'groups', '[]'::jsonb)) > 0
),
-- Consumers con al menos una auth api_key activa: los únicos cuyo tráfico
-- puede llegar con el principal inerte.
apikey_consumers AS (
    SELECT DISTINCT c.id, c.gateway_id, c.name, c.type
    FROM consumers c
    JOIN consumer_auth ca ON ca.consumer_id = c.id
    JOIN auths a ON a.id = ca.auth_id
    WHERE c.active AND a.enabled AND a.type = 'api_key'
)
-- Camino 1: la policy está asignada explícitamente a ese consumer.
SELECT 'asignada' AS via, s.gateway_id, s.name AS policy, s.slug,
       s.groups::text AS groups, k.name AS consumer, k.type AS consumer_type
FROM scoped s
JOIN consumer_policy cp ON cp.policy_id = s.id
JOIN apikey_consumers k ON k.id = cp.consumer_id
UNION ALL
-- Camino 2: la policy es global, así que alcanza a todos los consumers del gateway
-- sin que nadie la haya asignado. Es el camino que más sorprende.
SELECT 'global', s.gateway_id, s.name, s.slug,
       s.groups::text, k.name, k.type
FROM scoped s
JOIN apikey_consumers k ON k.gateway_id = s.gateway_id
WHERE s.global
ORDER BY gateway_id, policy, consumer;
