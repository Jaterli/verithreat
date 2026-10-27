-- VeriThreat · migración 003: claves de API por organización (paso 6b, Gateway)
--
-- Solo se guarda el sha256 de cada clave: son aleatorias de 192 bits, así que no hace falta un hash lento. La clave
-- en claro se muestra una vez al crearla (services/gateway/scripts/new-api-key.sh) y no se guarda en ningún sitio.
-- Revocar:  UPDATE verithreat.api_key SET revoked_at = now() WHERE id = <id>;  (efectivo en el Gateway en ≤ 60 s)
--
-- Aplicar sobre una base existente:  docker compose exec -T postgres psql -U verithreat -d verithreat < db/migrations/003_api_keys.sql
-- Es idempotente.

SET search_path TO verithreat;

CREATE TABLE IF NOT EXISTS api_key (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization text        NOT NULL REFERENCES source,
    key_sha256   char(64)    NOT NULL UNIQUE CHECK (key_sha256 ~ '^[0-9a-f]{64}$'),
    label        text,                                  -- para qué o para quién se emitió
    created_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz
);
CREATE INDEX IF NOT EXISTS api_key_organization_idx ON api_key (organization);
