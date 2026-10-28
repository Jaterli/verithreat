#!/usr/bin/env bash
# VeriThreat · red Hyperledger Fabric de prueba (paso 6c). Usa la test-network oficial de fabric-samples (2.5 LTS):
# dos organizaciones (Org1MSP = org-alpha, Org2MSP = org-beta), un orderer y el canal iocchannel.
#
#   ./network.sh up       levanta la red, crea el canal y fija los anchor peers
#   ./network.sh anchors  fija los anchor peers de las dos organizaciones (idempotente; no necesita jq)
#   ./network.sh deploy   compila el chaincode iocregistry (Maven) y lo instala, aprueba y confirma en el canal
#   ./network.sh smoke    registra un IOC desde cada organización y lo consulta
#   ./network.sh down     para la red y borra su estado (certificados, ledger, contenedores)
#
# Requisitos (WSL): Docker en marcha y fabric-samples con binarios e imágenes 2.5.16 en $FABRIC_SAMPLES
# (por defecto ~/fabric/fabric-samples). Para redesplegar un chaincode cambiado: CC_VERSION=0.1.1 CC_SEQUENCE=2 ./network.sh deploy
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
FABRIC_SAMPLES=${FABRIC_SAMPLES:-$HOME/fabric/fabric-samples}
TN=$FABRIC_SAMPLES/test-network
CHANNEL=${CHANNEL:-iocchannel}
CC_NAME=iocregistry
CC_SRC=$HERE/chaincode/iocregistry
CC_VERSION=${CC_VERSION:-0.1.0}
CC_SEQUENCE=${CC_SEQUENCE:-1}

[ -d "$TN" ] || { echo "fabric-samples not found in $FABRIC_SAMPLES (set FABRIC_SAMPLES)" >&2; exit 1; }
export PATH=$FABRIC_SAMPLES/bin:$PATH
export FABRIC_CFG_PATH=$FABRIC_SAMPLES/config
export CORE_PEER_TLS_ENABLED=true
ORDERER_CA=$TN/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem
ORG1_CA=$TN/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem
ORG2_CA=$TN/organizations/peerOrganizations/org2.example.com/tlsca/tlsca.org2.example.com-cert.pem
ORDERER=(-o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA")
BOTH_PEERS=(--peerAddresses localhost:7051 --tlsRootCertFiles "$ORG1_CA" --peerAddresses localhost:9051 --tlsRootCertFiles "$ORG2_CA")

# Identidad de administrador de la organización 1 o 2 para los comandos peer
as_org() {
  if [ "$1" = 1 ]; then
    export CORE_PEER_LOCALMSPID=Org1MSP CORE_PEER_ADDRESS=localhost:7051 CORE_PEER_TLS_ROOTCERT_FILE=$ORG1_CA
    export CORE_PEER_MSPCONFIGPATH=$TN/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
  else
    export CORE_PEER_LOCALMSPID=Org2MSP CORE_PEER_ADDRESS=localhost:9051 CORE_PEER_TLS_ROOTCERT_FILE=$ORG2_CA
    export CORE_PEER_MSPCONFIGPATH=$TN/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
  fi
}

up() {
  # El script oficial fija los anchor peers con jq; si jq no está, ese último paso falla y lo hace anchors()
  (cd "$TN" && ./network.sh up createChannel -c "$CHANNEL") || true
  anchors
}

# Anchor peers: sin ellos, el descubrimiento de servicio (que usa el SDK Fabric Gateway del paso 6d) no ve los peers
# de la otra organización. Mismo procedimiento que setAnchorPeer.sh de fabric-samples, editando el JSON con Python.
anchors() {
  local work
  work=$(mktemp -d)
  for org in 1 2; do
    as_org $org
    local msp=$CORE_PEER_LOCALMSPID host=peer0.org$org.example.com port
    port=$([ $org = 1 ] && echo 7051 || echo 9051)
    peer channel fetch config "$work/block.pb" "${ORDERER[@]}" -c "$CHANNEL" 2>/dev/null
    configtxlator proto_decode --input "$work/block.pb" --type common.Block --output "$work/block.json"
    python3 - "$work" "$msp" "$host" "$port" <<'PY'
import json, sys
work, msp, host, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
config = json.load(open(f"{work}/block.json"))["data"]["data"][0]["payload"]["data"]["config"]
json.dump(config, open(f"{work}/config.json", "w"))
values = config["channel_group"]["groups"]["Application"]["groups"][msp]["values"]
values["AnchorPeers"] = {"mod_policy": "Admins", "version": "0",
                         "value": {"anchor_peers": [{"host": host, "port": port}]}}
json.dump(config, open(f"{work}/modified.json", "w"))
PY
    configtxlator proto_encode --input "$work/config.json" --type common.Config --output "$work/config.pb"
    configtxlator proto_encode --input "$work/modified.json" --type common.Config --output "$work/modified.pb"
    if ! configtxlator compute_update --channel_id "$CHANNEL" --original "$work/config.pb" \
         --updated "$work/modified.pb" --output "$work/update.pb" 2>/dev/null; then
      echo "== anchor peer for $msp already set"
      continue
    fi
    configtxlator proto_decode --input "$work/update.pb" --type common.ConfigUpdate --output "$work/update.json"
    python3 - "$work" "$CHANNEL" <<'PY'
import json, sys
work, channel = sys.argv[1], sys.argv[2]
update = json.load(open(f"{work}/update.json"))
envelope = {"payload": {"header": {"channel_header": {"channel_id": channel, "type": 2}},
                        "data": {"config_update": update}}}
json.dump(envelope, open(f"{work}/envelope.json", "w"))
PY
    configtxlator proto_encode --input "$work/envelope.json" --type common.Envelope --output "$work/anchors.tx"
    peer channel update -f "$work/anchors.tx" -c "$CHANNEL" "${ORDERER[@]}" 2>&1 | grep -E 'Successfully|Error' || true
    echo "== anchor peer for $msp: $host:$port"
  done
  rm -rf "$work"
}

down() {
  (cd "$TN" && ./network.sh down)
}

deploy() {
  echo "== building chaincode.jar"
  (cd "$CC_SRC" && mvn -q -B package)
  # Se empaqueta el jar ya compilado: el contenedor de Fabric lo ejecuta sin descargar ni compilar nada
  local stage pkg
  stage=$(mktemp -d)
  pkg=$(mktemp -d)/$CC_NAME.tar.gz
  cp "$CC_SRC/target/chaincode.jar" "$stage/"
  peer lifecycle chaincode package "$pkg" --path "$stage" --lang java --label "${CC_NAME}_${CC_VERSION}"
  local pkg_id
  pkg_id=$(peer lifecycle chaincode calculatepackageid "$pkg")
  for org in 1 2; do
    as_org $org
    echo "== installing on Org$org (first time pulls the fabric-javaenv image)"
    peer lifecycle chaincode install "$pkg" || echo "   (already installed)"
    echo "== approving for Org$org"
    peer lifecycle chaincode approveformyorg "${ORDERER[@]}" --channelID "$CHANNEL" --name "$CC_NAME" \
      --version "$CC_VERSION" --package-id "$pkg_id" --sequence "$CC_SEQUENCE"
  done
  peer lifecycle chaincode checkcommitreadiness --channelID "$CHANNEL" --name "$CC_NAME" --version "$CC_VERSION" \
    --sequence "$CC_SEQUENCE" --output json
  echo "== committing"
  peer lifecycle chaincode commit "${ORDERER[@]}" --channelID "$CHANNEL" --name "$CC_NAME" --version "$CC_VERSION" \
    --sequence "$CC_SEQUENCE" "${BOTH_PEERS[@]}"
  peer lifecycle chaincode querycommitted --channelID "$CHANNEL" --name "$CC_NAME"
}

invoke() { # org, json
  as_org "$1"
  peer chaincode invoke "${ORDERER[@]}" -C "$CHANNEL" -n "$CC_NAME" "${BOTH_PEERS[@]}" -c "$2" --waitForEvent
}

query() { # org, json
  as_org "$1"
  peer chaincode query -C "$CHANNEL" -n "$CC_NAME" -c "$2"
}

smoke() {
  # Huella de un valor de prueba (en VeriThreat es la columna fingerprint: sha256 del valor normalizado)
  local fp
  fp=$(printf '%s' "smoke-test.verithreat.invalid" | sha256sum | cut -d' ' -f1)
  echo "== Org1 registers domain $fp"
  invoke 1 "{\"function\":\"RegisterIoc\",\"Args\":[\"domain\",\"$fp\",\"phishing\"]}"
  echo "== Org2 registers the same indicator"
  invoke 2 "{\"function\":\"RegisterIoc\",\"Args\":[\"domain\",\"$fp\",\"c2\"]}"
  echo "== records of that indicator (queried by Org2)"
  query 2 "{\"function\":\"GetRecordsByIndicator\",\"Args\":[\"$fp\"]}"
  echo
  echo "== invalid fingerprint must be rejected"
  invoke 1 '{"function":"RegisterIoc","Args":["domain","ABC","phishing"]}' && echo "UNEXPECTED: accepted" || echo "rejected as expected"
}

case "${1:-}" in
  up) up ;;
  anchors) anchors ;;
  deploy) deploy ;;
  smoke) smoke ;;
  down) down ;;
  *) echo "usage: $0 up|deploy|smoke|down" >&2; exit 1 ;;
esac
