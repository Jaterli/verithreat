package com.verithreat.chaincode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.contract.ContractInterface;
import org.hyperledger.fabric.contract.annotation.Contact;
import org.hyperledger.fabric.contract.annotation.Contract;
import org.hyperledger.fabric.contract.annotation.Default;
import org.hyperledger.fabric.contract.annotation.Info;
import org.hyperledger.fabric.contract.annotation.Transaction;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ledger.CompositeKey;
import org.hyperledger.fabric.shim.ledger.KeyValue;
import org.hyperledger.fabric.shim.ledger.QueryResultsIterator;

/**
 * Registro inmutable de los IOCs que aportan las organizaciones de VeriThreat (decisión 14 de CLAUDE.md).
 *
 * <p>En la cadena NO va el valor del IOC, sino su huella (sha256 del valor normalizado, la columna fingerprint de la
 * base de datos): quien tenga el IOC puede comprobar su registro, pero la cadena no expone los indicadores. La
 * organización se toma del certificado que firma la transacción (MSP), nunca de un parámetro, y la fecha es la de la
 * transacción, la misma en todos los nodos que la avalan. Con eso el chaincode calcula el hash canónico
 * sha256(tipo | huella | MSP | fecha) y guarda un registro que no se puede modificar.
 */
@Contract(name = "iocregistry",
        info = @Info(title = "VeriThreat IOC registry", description = "Provenance of the IOCs shared by organizations",
                version = "0.1.0", contact = @Contact(name = "VeriThreat")))
@Default
public final class IocRegistryContract implements ContractInterface {

    /** Los mismos tipos y categorías que la base de datos (db/schema.sql). */
    static final Set<String> TYPES = Set.of("sha256", "md5", "sha1", "domain", "url", "ip", "cidr");
    static final Set<String> CATEGORIES = Set.of("malware_distribution", "c2", "phishing", "skimming", "malware",
            "attack_source", "attack_network", "other", "unspecified");
    private static final Pattern SHA256_HEX = Pattern.compile("[0-9a-f]{64}");
    /** Índice por huella del indicador: «indicator» + huella + hash canónico. */
    static final String INDEX = "indicator";

    enum Errors { INVALID_ARGUMENT, ALREADY_REGISTERED, NOT_FOUND }

    /**
     * Registra la aportación de un IOC por la organización que firma la transacción. Devuelve el registro (JSON) con
     * su hash canónico, que el servicio de IOCs guarda junto a la observación.
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public String RegisterIoc(final Context ctx, final String type, final String indicatorFingerprint,
                              final String category) {
        if (!TYPES.contains(type)) {
            throw new ChaincodeException("unknown type: " + type, Errors.INVALID_ARGUMENT.toString());
        }
        if (indicatorFingerprint == null || !SHA256_HEX.matcher(indicatorFingerprint).matches()) {
            throw new ChaincodeException("indicatorFingerprint must be 64 lowercase hex characters",
                    Errors.INVALID_ARGUMENT.toString());
        }
        if (!CATEGORIES.contains(category)) {
            throw new ChaincodeException("unknown category: " + category, Errors.INVALID_ARGUMENT.toString());
        }
        ChaincodeStub stub = ctx.getStub();
        String msp = ctx.getClientIdentity().getMSPID();
        Instant ts = stub.getTxTimestamp();
        String registeredAt = ts.toString();
        String canonical = sha256Hex(type + "|" + indicatorFingerprint + "|" + msp + "|" + registeredAt);
        String existing = stub.getStringState(canonical);
        if (existing != null && !existing.isEmpty()) {
            throw new ChaincodeException("already registered: " + canonical, Errors.ALREADY_REGISTERED.toString());
        }
        // Orden fijo de campos: el JSON sale igual en todos los nodos (los avales tienen que coincidir byte a byte)
        Map<String, String> record = new LinkedHashMap<>();
        record.put("canonicalHash", canonical);
        record.put("type", type);
        record.put("indicatorFingerprint", indicatorFingerprint);
        record.put("category", category);
        record.put("mspId", msp);
        record.put("registeredAt", registeredAt);
        record.put("txId", stub.getTxId());
        String json = toJson(record);
        stub.putStringState(canonical, json);
        CompositeKey index = stub.createCompositeKey(INDEX, indicatorFingerprint, canonical);
        stub.putStringState(index.toString(), "\u0000");
        return json;
    }

    /** Un registro por su hash canónico. */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String GetRecord(final Context ctx, final String canonicalHash) {
        String json = ctx.getStub().getStringState(canonicalHash);
        if (json == null || json.isEmpty()) {
            throw new ChaincodeException("record not found: " + canonicalHash, Errors.NOT_FOUND.toString());
        }
        return json;
    }

    /** Todos los registros de un indicador (por la huella de su valor), de todas las organizaciones. */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String GetRecordsByIndicator(final Context ctx, final String indicatorFingerprint) {
        ChaincodeStub stub = ctx.getStub();
        List<String> records = new ArrayList<>();
        try (QueryResultsIterator<KeyValue> it = stub.getStateByPartialCompositeKey(
                stub.createCompositeKey(INDEX, indicatorFingerprint))) {
            for (KeyValue kv : it) {
                List<String> attrs = stub.splitCompositeKey(kv.getKey()).getAttributes();
                String json = stub.getStringState(attrs.get(1));
                if (json != null && !json.isEmpty()) {
                    records.add(json); // cada registro ya es un objeto JSON
                }
            }
        } catch (Exception e) {
            if (e instanceof ChaincodeException) {
                throw (ChaincodeException) e;
            }
            throw new ChaincodeException("error reading the index: " + e.getMessage());
        }
        return "[" + String.join(",", records) + "]";
    }

    /** Objeto JSON plano de cadenas, en el orden del mapa (sin dependencias externas). */
    static String toJson(Map<String, String> fields) {
        StringBuilder sb = new StringBuilder("{");
        for (Map.Entry<String, String> e : fields.entrySet()) {
            if (sb.length() > 1) {
                sb.append(',');
            }
            sb.append('"').append(escape(e.getKey())).append("\":\"").append(escape(e.getValue())).append('"');
        }
        return sb.append('}').toString();
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') {
                sb.append('\\').append(c);
            } else if (c < 0x20) {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    static String sha256Hex(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : d) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
