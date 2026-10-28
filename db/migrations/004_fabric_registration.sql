-- VeriThreat · migración 004: registro en Fabric de las aportaciones (paso 6d, patrón «bandeja de salida»)
--
-- Al aceptar una aportación nueva, ioc-service inserta en la MISMA transacción una fila 'pending' aquí. Un proceso del
-- propio servicio la envía a Fabric (chaincode iocregistry) y reintenta con espera creciente si Fabric no responde:
-- ninguna aportación se pierde aunque la red esté caída.
--   pending     a la espera de registrarse (o reintentando: attempts, next_attempt_at, last_error)
--   registered  registrada: canonical_hash, tx_id, msp_id y registered_at vienen del chaincode
--   failed      rechazada por el chaincode (error permanente, no se reintenta)
--
-- Aplicar sobre una base existente:  docker compose exec -T postgres psql -U verithreat -d verithreat < db/migrations/004_fabric_registration.sql
-- Es idempotente.

SET search_path TO verithreat;

CREATE TABLE IF NOT EXISTS fabric_registration (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sighting_id           bigint      NOT NULL UNIQUE REFERENCES sighting ON DELETE CASCADE,
    organization          text        NOT NULL REFERENCES source,
    indicator_type        text        NOT NULL,
    indicator_fingerprint char(64)    NOT NULL CHECK (indicator_fingerprint ~ '^[0-9a-f]{64}$'),
    category              text        NOT NULL,
    status                text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'registered', 'failed')),
    attempts              integer     NOT NULL DEFAULT 0,
    next_attempt_at       timestamptz NOT NULL DEFAULT now(),
    last_error            text,
    canonical_hash        char(64)    CHECK (canonical_hash ~ '^[0-9a-f]{64}$'),
    tx_id                 text,
    msp_id                text,
    registered_at         timestamptz,                       -- fecha de la transacción en Fabric
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CHECK (status <> 'registered' OR (canonical_hash IS NOT NULL AND tx_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS fabric_registration_due_idx ON fabric_registration (next_attempt_at) WHERE status = 'pending';

-- Las aportaciones anteriores a esta migración también se registran
INSERT INTO fabric_registration (sighting_id, organization, indicator_type, indicator_fingerprint, category)
SELECT s.id, s.source, i.type, encode(i.fingerprint, 'hex'), s.category
FROM sighting s
JOIN source src ON src.code = s.source AND src.role = 'organization'
JOIN indicator i ON i.id = s.indicator_id
ON CONFLICT (sighting_id) DO NOTHING;
