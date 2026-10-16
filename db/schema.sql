-- VeriThreat · esquema de la base de datos de indicadores (PostgreSQL 15 o superior)
--
-- Modelo: un INDICATOR único (type, value normalizado) con una o varias SIGHTINGS (observaciones), una por registro de
-- cada fuente. Cada carga de un fichero crudo queda registrada en DOWNLOAD (huella sha256 y fecha), lo que hace la
-- carga idempotente: volver a cargar el mismo fichero no cambia nada. Ver CLAUDE.md, sección 4.
--
-- Se aplica sola al crear el contenedor (docker-compose.yml) y se puede relanzar: todo es IF NOT EXISTS / OR REPLACE.

CREATE SCHEMA IF NOT EXISTS verithreat;
SET search_path TO verithreat;

-- ----------------------------------------------------------------------------------------------- catálogo de fuentes
-- La familia agrupa fuentes que no son independientes (ThreatFox y URLhaus = abuse.ch): la corroboración se cuenta
-- por familias, no por observaciones.
CREATE TABLE IF NOT EXISTS source (
    code        text PRIMARY KEY,
    family      text NOT NULL,
    role        text NOT NULL CHECK (role IN ('indicators', 'signal')),
    description text NOT NULL
);

INSERT INTO source (code, family, role, description) VALUES
    ('threatfox',    'abuse.ch',     'indicators', 'Mixed IOCs with malware family, confidence and C2'),
    ('urlhaus',      'abuse.ch',     'indicators', 'Malware distribution URLs with online/offline status'),
    ('blocklist.de', 'blocklist.de', 'indicators', 'IPs attacking services; full /24 blocks stored as cidr'),
    ('phishtank',    'phishtank',    'indicators', 'Community-verified phishing (90-day window)'),
    ('tweetfeed',    'tweetfeed',    'indicators', 'IOCs shared by researchers on Twitter/X, with reporter and tags'),
    ('ipsum',        'ipsum',        'signal',     'Number of public lists an IP appears in (provides no indicators)')
ON CONFLICT (code) DO NOTHING;

-- ----------------------------------------------------------------------------------------------- descargas
-- Una fila por fichero crudo cargado. El fichero se identifica por su contenido (sha256), no por su nombre: las
-- exportaciones de abuse.ch se regeneran con el mismo nombre. «file_name» es solo el nombre, nunca la URL de descarga
-- (las de abuse.ch llevan la clave en la ruta).
CREATE TABLE IF NOT EXISTS download (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source     text        NOT NULL REFERENCES source,
    file_name  text        NOT NULL CHECK (file_name !~ '[/\\]'),
    sha256     char(64)    NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes bigint      NOT NULL CHECK (size_bytes >= 0),
    rows_read  integer     NOT NULL CHECK (rows_read >= 0),   -- filas leídas del fichero
    fetched_at timestamptz NOT NULL,                          -- fecha de la foto de la fuente
    loaded_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source, sha256)
);

-- ----------------------------------------------------------------------------------------------- indicadores
-- «fingerprint» = sha256 del valor en UTF-8: garantiza la unicidad aunque haya URLs de más de 2,7 kB (PhishTank llega
-- a 25.000 caracteres, más de lo que admite un índice sobre el texto) y servirá para el hash canónico de Fabric.
-- convert_to() no es IMMUTABLE para PostgreSQL (depende del nombre de la codificación); se declara aquí porque la base
-- de datos se crea en UTF-8 y la codificación de destino es fija.
CREATE OR REPLACE FUNCTION fingerprint(value text) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN sha256(convert_to(value, 'UTF8'));

CREATE TABLE IF NOT EXISTS indicator (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    type        text        NOT NULL CHECK (type IN ('sha256', 'md5', 'sha1', 'domain', 'url', 'ip', 'cidr')),
    value       text        NOT NULL CHECK (value <> ''),
    fingerprint bytea       NOT NULL GENERATED ALWAYS AS (fingerprint(value)) STORED,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (type, fingerprint),
    -- Formato normalizado según el tipo (el que producen los cargadores). Hosts y hashes en minúsculas; las URLs
    -- conservan su capitalización; IPs en forma canónica (IPv6 comprimida).
    CONSTRAINT normalized_value CHECK (
        CASE type
            WHEN 'sha256' THEN value ~ '^[0-9a-f]{64}$'
            WHEN 'sha1'   THEN value ~ '^[0-9a-f]{40}$'
            WHEN 'md5'    THEN value ~ '^[0-9a-f]{32}$'
            WHEN 'domain' THEN value = lower(value) AND value !~ '[/:@[:space:]]'
            WHEN 'url'    THEN value ~* '^[a-z][a-z0-9+.-]*://'
            WHEN 'ip'     THEN host(value::inet) = value AND masklen(value::inet) IN (32, 128)
            WHEN 'cidr'   THEN value::cidr::text = value
        END)
);

-- ----------------------------------------------------------------------------------------------- observaciones
-- Una fila por registro de una fuente. Reglas de la carga (ai/src/load_db.py):
--   - (source, source_record_id) identifica la observación: si vuelve a aparecer en una descarga posterior no se
--     duplica; se actualizan last_confirmed_at, status, corroborated y last_download_id.
--   - seen_at: fecha que da la fuente (o la de descarga si no la trae, como blocklist.de); no cambia.
--   - last_confirmed_at: última descarga en la que seguía apareciendo. Alimenta el decaimiento de la severidad.
--   - raw: el registro original, para auditar y poder renormalizar sin volver a descargar.
CREATE TABLE IF NOT EXISTS sighting (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator_id      bigint      NOT NULL REFERENCES indicator ON DELETE CASCADE,
    source            text        NOT NULL REFERENCES source,
    source_record_id  text        NOT NULL,
    category          text        NOT NULL CHECK (category IN ('malware_distribution', 'c2', 'phishing', 'skimming',
                                      'malware', 'attack_source', 'attack_network', 'other', 'unspecified')),
    seen_at           timestamptz NOT NULL,
    last_confirmed_at timestamptz NOT NULL,
    malware_family    text,
    confidence        smallint    CHECK (confidence BETWEEN 0 AND 100),   -- ThreatFox
    status            text,                                               -- URLhaus: online / offline
    reporter          text,
    corroborated      boolean,                                            -- TweetFeed: lo reportan otros feeds
    raw               jsonb       NOT NULL,
    first_download_id bigint      NOT NULL REFERENCES download,
    last_download_id  bigint      NOT NULL REFERENCES download,
    UNIQUE (source, source_record_id)
);
CREATE INDEX IF NOT EXISTS sighting_indicator_idx ON sighting (indicator_id);

-- ----------------------------------------------------------------------------------------------- señal de IPsum
-- Nivel de IPsum (nº de listas) de cada IP indicador en cada descarga de IPsum. Va aparte de la observación porque
-- es una propiedad de la IP en un día, no de un registro de una fuente. Solo se guardan las IPs que ya son
-- indicadores; la ausencia en la última descarga equivale a nivel 0.
CREATE TABLE IF NOT EXISTS ipsum_signal (
    indicator_id bigint   NOT NULL REFERENCES indicator ON DELETE CASCADE,
    download_id  bigint   NOT NULL REFERENCES download,
    level        smallint NOT NULL CHECK (level BETWEEN 1 AND 8),
    PRIMARY KEY (indicator_id, download_id)
);

-- ----------------------------------------------------------------------------------------------- modelo y puntuación
-- Cada versión entrenada del modelo A, con sus parámetros y métricas. Solo una versión activa por modelo.
CREATE TABLE IF NOT EXISTS model_version (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name            text        NOT NULL,                 -- p. ej. 'model_a'
    version         text        NOT NULL,
    trained_at      timestamptz NOT NULL,
    artifact_sha256 char(64)    NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    params          jsonb       NOT NULL,                 -- hiperparámetros, semilla, datos de entrenamiento
    metrics         jsonb       NOT NULL,                 -- PR-AUC, ROC-AUC, tamaño y fecha del test
    active          boolean     NOT NULL DEFAULT false,
    UNIQUE (name, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS model_version_one_active ON model_version (name) WHERE active;

-- Historial de puntuaciones: cada cálculo es una fila nueva. Los componentes del score se guardan por separado
-- (explicabilidad); su contenido exacto se fija con la fórmula de severidad (paso 5 de CLAUDE.md).
CREATE TABLE IF NOT EXISTS score (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator_id     bigint      NOT NULL REFERENCES indicator ON DELETE CASCADE,
    computed_at      timestamptz NOT NULL DEFAULT now(),
    model_version_id bigint      REFERENCES model_version,  -- NULL si el modelo no aplica (IPs, hashes, cidr)
    p_malicious      real        CHECK (p_malicious BETWEEN 0 AND 1),
    components       jsonb       NOT NULL,
    severity         smallint    NOT NULL CHECK (severity BETWEEN 0 AND 100),
    disputed         boolean     NOT NULL DEFAULT false,
    CHECK ((model_version_id IS NULL) = (p_malicious IS NULL))
);
CREATE INDEX IF NOT EXISTS score_latest_idx ON score (indicator_id, computed_at DESC);

-- ----------------------------------------------------------------------------------------------- vistas
-- Resumen por indicador: lo que necesitan las reglas de severidad (fuentes, familias, categorías, fechas e IPsum).
CREATE OR REPLACE VIEW v_indicator AS
WITH latest_ipsum AS (
    SELECT id FROM download WHERE source = 'ipsum' ORDER BY fetched_at DESC, id DESC LIMIT 1
)
SELECT i.id,
       i.type,
       i.value,
       min(s.seen_at)                                           AS first_seen,
       max(s.last_confirmed_at)                                 AS last_confirmed,
       count(*)                                                 AS n_sightings,
       count(DISTINCT s.source)                                 AS n_sources,
       count(DISTINCT src.family)                               AS n_families,
       array_agg(DISTINCT s.category ORDER BY s.category)       AS categories,
       CASE WHEN i.type = 'ip' THEN coalesce(ip.level, 0) END   AS ipsum_level
FROM indicator i
JOIN sighting s   ON s.indicator_id = i.id
JOIN source src   ON src.code = s.source
LEFT JOIN ipsum_signal ip ON ip.indicator_id = i.id AND ip.download_id = (SELECT id FROM latest_ipsum)
GROUP BY i.id, ip.level;

-- Última puntuación de cada indicador.
CREATE OR REPLACE VIEW v_current_score AS
SELECT DISTINCT ON (indicator_id) *
FROM score
ORDER BY indicator_id, computed_at DESC, id DESC;
