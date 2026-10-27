package com.verithreat.gateway;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

/**
 * Resuelve la organización de una clave de API. Solo se compara el sha256 de la clave con la tabla api_key (nunca se
 * guarda la clave). Las claves válidas se recuerdan unos segundos para no consultar la base de datos en cada petición;
 * por eso una revocación tarda como mucho ese tiempo en aplicarse.
 */
@Service
public class ApiKeyService {

    private record Entry(String organization, Instant expires) {
    }

    private final JdbcClient jdbc;
    private final Duration ttl;
    private final Map<String, Entry> cache = new ConcurrentHashMap<>();

    public ApiKeyService(JdbcClient jdbc, @Value("${verithreat.api-key-cache-seconds:60}") long ttlSeconds) {
        this.jdbc = jdbc;
        this.ttl = Duration.ofSeconds(ttlSeconds);
    }

    public Optional<String> organizationFor(String apiKey) {
        if (apiKey == null || apiKey.isBlank() || apiKey.length() > 200) {
            return Optional.empty();
        }
        String hash = sha256Hex(apiKey.strip());
        Entry e = cache.get(hash);
        if (e != null && e.expires().isAfter(Instant.now())) {
            return Optional.of(e.organization());
        }
        Optional<String> org = jdbc.sql("""
                        SELECT k.organization FROM api_key k
                        JOIN source s ON s.code = k.organization AND s.role = 'organization'
                        WHERE k.key_sha256 = :hash AND k.revoked_at IS NULL""")
                .param("hash", hash).query(String.class).optional();
        org.ifPresentOrElse(o -> cache.put(hash, new Entry(o, Instant.now().plus(ttl))), () -> cache.remove(hash));
        return org;
    }

    static String sha256Hex(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(d);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
