-- VeriThreat · migración 002: organizaciones como fuentes (decisión 14 de CLAUDE.md, 27-10-2026)
--
-- Una organización participante es una fuente más (papel 'organization', su propia familia): sus aportaciones son
-- observaciones normales, salen en las consultas y cuentan para la corroboración entre familias.
-- Una aportación no viene de ninguna descarga, así que first/last_download_id pasan a ser opcionales; las
-- observaciones de los feeds los siguen teniendo siempre (load_db.py los rellena).
--
-- Aplicar sobre una base existente:  docker compose exec -T postgres psql -U verithreat -d verithreat < db/migrations/002_organizations.sql
-- En un contenedor nuevo se aplica sola tras db/schema.sql (docker-compose.yml). Es idempotente.

SET search_path TO verithreat;

ALTER TABLE source DROP CONSTRAINT IF EXISTS source_role_check;
ALTER TABLE source ADD CONSTRAINT source_role_check CHECK (role IN ('indicators', 'signal', 'organization'));

ALTER TABLE sighting ALTER COLUMN first_download_id DROP NOT NULL;
ALTER TABLE sighting ALTER COLUMN last_download_id DROP NOT NULL;

-- Organizaciones de prueba para el TFM (la red Fabric tendrá dos organizaciones)
INSERT INTO source (code, family, role, description) VALUES
    ('org-alpha', 'org-alpha', 'organization', 'Test organization A (Fabric Org1)'),
    ('org-beta',  'org-beta',  'organization', 'Test organization B (Fabric Org2)')
ON CONFLICT (code) DO NOTHING;
