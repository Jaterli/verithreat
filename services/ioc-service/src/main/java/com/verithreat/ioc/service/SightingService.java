package com.verithreat.ioc.service;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.verithreat.ioc.api.Dtos.SightingRequest;
import com.verithreat.ioc.api.Dtos.SightingResponse;
import com.verithreat.ioc.normalize.InvalidIndicatorException;
import com.verithreat.ioc.normalize.Normalizer;
import com.verithreat.ioc.repo.IndicatorRepository;
import com.verithreat.ioc.repo.IndicatorRepository.IndicatorRecord;

import tools.jackson.databind.json.JsonMapper;

/**
 * Aportación de un IOC por una organización (decisión 14 de CLAUDE.md): el IOC se guarda como una observación más,
 * con la organización como fuente. Volver a aportar el mismo IOC no lo duplica: renueva su última confirmación.
 */
@Service
public class SightingService {

    /** Las mismas categorías que admite la tabla sighting (db/schema.sql). */
    public static final Set<String> CATEGORIES = Set.of("malware_distribution", "c2", "phishing", "skimming", "malware",
            "attack_source", "attack_network", "other", "unspecified");

    /** Margen para relojes desajustados: una fecha de observación no puede estar más adelante que esto. */
    private static final Duration FUTURE_TOLERANCE = Duration.ofMinutes(5);

    private final JdbcClient jdbc;
    private final IndicatorRepository indicators;
    private final JsonMapper json;

    public SightingService(JdbcClient jdbc, IndicatorRepository indicators, JsonMapper json) {
        this.jdbc = jdbc;
        this.indicators = indicators;
        this.json = json;
    }

    /** Lanza {@link UnknownOrganizationException} si el código no es una organización registrada. */
    public void requireOrganization(String organization) {
        Integer n = jdbc.sql("SELECT count(*) FROM source WHERE code = :code AND role = 'organization'")
                .param("code", organization).query(Integer.class).single();
        if (n == 0) {
            throw new UnknownOrganizationException(organization);
        }
    }

    @Transactional
    public SightingResponse submit(String organization, SightingRequest req) {
        requireOrganization(organization);
        if (!CATEGORIES.contains(req.category())) {
            throw new InvalidIndicatorException("unknown category: " + req.category() + " (allowed: " + CATEGORIES + ")");
        }
        String value = Normalizer.normalize(req.type(), req.value());
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime seenAt = req.seenAt() == null ? now : req.seenAt();
        if (seenAt.isAfter(now.plus(FUTURE_TOLERANCE))) {
            throw new InvalidIndicatorException("seenAt is in the future: " + seenAt);
        }

        jdbc.sql("INSERT INTO indicator (type, value) VALUES (:type, :value) ON CONFLICT (type, fingerprint) DO NOTHING")
                .param("type", req.type()).param("value", value).update();
        IndicatorRecord ind = indicators.findByValue(req.type(), value).orElseThrow();

        // El registro original de la aportación, como `raw` en las observaciones de los feeds
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("organization", organization);
        raw.put("type", req.type());
        raw.put("value", req.value());
        raw.put("category", req.category());
        raw.put("seen_at", req.seenAt() == null ? null : req.seenAt().toString());
        raw.put("malware_family", req.malwareFamily());
        raw.put("confidence", req.confidence());
        raw.put("description", req.description());
        raw.put("submitted_at", now.toString());

        // Identificador del registro = tipo + huella: la misma organización y el mismo IOC son la misma observación
        record Row(long id, boolean inserted) {
        }
        Row row = jdbc.sql("""
                        INSERT INTO sighting AS s (indicator_id, source, source_record_id, category, seen_at,
                                                   last_confirmed_at, malware_family, confidence, raw)
                        VALUES (:indicator, :org, :type || ':' || :fp, :category, :seenAt, :now, :family, :confidence,
                                CAST(:raw AS jsonb))
                        ON CONFLICT (source, source_record_id) DO UPDATE
                        SET last_confirmed_at = EXCLUDED.last_confirmed_at,
                            category          = EXCLUDED.category,
                            malware_family    = EXCLUDED.malware_family,
                            confidence        = EXCLUDED.confidence,
                            raw               = EXCLUDED.raw
                        RETURNING s.id, (xmax = 0) AS inserted""")
                .param("indicator", ind.id()).param("org", organization).param("type", req.type())
                .param("fp", ind.fingerprint()).param("category", req.category()).param("seenAt", seenAt)
                .param("now", now).param("family", req.malwareFamily()).param("confidence", req.confidence())
                .param("raw", json.writeValueAsString(raw))
                .query((rs, n) -> new Row(rs.getLong("id"), rs.getBoolean("inserted")))
                .single();

        // Bandeja de salida (paso 6d): en la misma transacción, así no hay aportación sin registro ni registro sin
        // aportación. Solo la primera vez: volver a aportar el mismo IOC no es una aportación nueva.
        if (row.inserted()) {
            jdbc.sql("""
                            INSERT INTO fabric_registration (sighting_id, organization, indicator_type,
                                                             indicator_fingerprint, category)
                            VALUES (:sighting, :org, :type, :fp, :category)""")
                    .param("sighting", row.id()).param("org", organization).param("type", ind.type())
                    .param("fp", ind.fingerprint()).param("category", req.category()).update();
        }
        String fabricStatus = jdbc.sql("SELECT status FROM fabric_registration WHERE sighting_id = :id")
                .param("id", row.id()).query(String.class).optional().orElse(null);

        var score = indicators.currentScore(ind.id()).orElse(null);
        return new SightingResponse(ind.id(), row.id(), ind.type(), ind.value(), ind.fingerprint(), row.inserted(),
                "pending", fabricStatus, score);
    }
}
