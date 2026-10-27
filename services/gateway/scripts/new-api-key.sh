#!/bin/sh
# Crea una clave de API para una organización y la muestra UNA vez; en la base de datos solo queda su sha256.
#   uso (desde WSL, en la raíz del repo o en cualquier sitio):  services/gateway/scripts/new-api-key.sh org-alpha "SOC de Alpha"
# Revocar:  docker compose exec -T postgres psql -U verithreat -d verithreat \
#             -c "UPDATE verithreat.api_key SET revoked_at = now() WHERE id = <id>"
set -eu
ORG="${1:?usage: new-api-key.sh <organization-code> [label]}"
LABEL="${2:-}"
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT"

KEY="vt_$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"   # 192 bits aleatorios
HASH=$(printf '%s' "$KEY" | sha256sum | cut -d' ' -f1)

ID=$(docker compose exec -T postgres psql -U verithreat -d verithreat -X -q -t -A -v ON_ERROR_STOP=1 \
       -v org="$ORG" -v hash="$HASH" -v label="$LABEL" <<'SQL'
SET search_path TO verithreat;
INSERT INTO api_key (organization, key_sha256, label)
SELECT code, :'hash', NULLIF(:'label', '') FROM source WHERE code = :'org' AND role = 'organization'
RETURNING id;
SQL
)
if [ -z "$ID" ]; then
  echo "ERROR: '$ORG' is not a registered organization (table source, role = 'organization')" >&2
  exit 1
fi
echo "API key #$ID for $ORG (shown only once, store it now):"
echo "$KEY"
