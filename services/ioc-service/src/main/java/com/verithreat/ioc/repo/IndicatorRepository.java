package com.verithreat.ioc.repo;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.verithreat.ioc.api.Dtos.IndicatorRow;
import com.verithreat.ioc.api.Dtos.Score;
import com.verithreat.ioc.api.Dtos.ScorePoint;
import com.verithreat.ioc.api.Dtos.Sighting;
import com.verithreat.ioc.api.Dtos.SightingSummary;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/** Consultas sobre el esquema verithreat (db/schema.sql). Los valores llegan ya normalizados. */
@Repository
public class IndicatorRepository {

    /** Fila básica de un indicador. */
    public record IndicatorRecord(long id, String type, String value, String fingerprint) {
    }

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    private final JdbcClient jdbc;
    private final JsonMapper json;

    public IndicatorRepository(JdbcClient jdbc, JsonMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    public Optional<IndicatorRecord> findByValue(String type, String normalizedValue) {
        return jdbc.sql("SELECT id, type, value, encode(fingerprint, 'hex') AS fp FROM indicator "
                        + "WHERE type = :type AND fingerprint = fingerprint(:value)")
                .param("type", type).param("value", normalizedValue)
                .query((rs, n) -> new IndicatorRecord(rs.getLong("id"), rs.getString("type"), rs.getString("value"),
                        rs.getString("fp")))
                .optional();
    }

    public Optional<IndicatorRecord> findById(long id) {
        return jdbc.sql("SELECT id, type, value, encode(fingerprint, 'hex') AS fp FROM indicator WHERE id = :id")
                .param("id", id)
                .query((rs, n) -> new IndicatorRecord(rs.getLong("id"), rs.getString("type"), rs.getString("value"),
                        rs.getString("fp")))
                .optional();
    }

    /** Última puntuación (la misma que da la vista v_current_score), o vacío si aún no se ha puntuado. */
    public Optional<Score> currentScore(long indicatorId) {
        return jdbc.sql("SELECT severity, disputed, p_malicious::float8 AS p_malicious, computed_at, "
                        + "components::text AS components "
                        + "FROM score WHERE indicator_id = :id ORDER BY computed_at DESC, id DESC LIMIT 1")
                .param("id", indicatorId)
                .query((rs, n) -> new Score(rs.getInt("severity"), rs.getBoolean("disputed"),
                        (Double) rs.getObject("p_malicious", Double.class), rs.getObject("computed_at", OffsetDateTime.class),
                        json.readValue(rs.getString("components"), MAP)))
                .optional();
    }

    public SightingSummary summary(long indicatorId) {
        List<String> sources = jdbc.sql("SELECT DISTINCT source FROM sighting WHERE indicator_id = :id ORDER BY 1")
                .param("id", indicatorId).query(String.class).list();
        return jdbc.sql("SELECT first_seen, last_confirmed, n_sightings, n_sources, n_families, categories, ipsum_level "
                        + "FROM v_indicator WHERE id = :id")
                .param("id", indicatorId)
                .query((rs, n) -> new SightingSummary(rs.getObject("first_seen", OffsetDateTime.class),
                        rs.getObject("last_confirmed", OffsetDateTime.class), rs.getInt("n_sightings"),
                        rs.getInt("n_sources"), rs.getInt("n_families"), textArray(rs, "categories"), sources,
                        (Integer) rs.getObject("ipsum_level", Integer.class)))
                .optional().orElse(null);
    }

    public List<Sighting> sightings(long indicatorId, int limit) {
        return jdbc.sql("SELECT source, category, seen_at, last_confirmed_at, status, malware_family, confidence, "
                        + "reporter, corroborated FROM sighting WHERE indicator_id = :id "
                        + "ORDER BY last_confirmed_at DESC, id DESC LIMIT :limit")
                .param("id", indicatorId).param("limit", limit)
                .query((rs, n) -> new Sighting(rs.getString("source"), rs.getString("category"),
                        rs.getObject("seen_at", OffsetDateTime.class), rs.getObject("last_confirmed_at", OffsetDateTime.class),
                        rs.getString("status"), rs.getString("malware_family"),
                        (Integer) rs.getObject("confidence", Integer.class), rs.getString("reporter"),
                        (Boolean) rs.getObject("corroborated", Boolean.class)))
                .list();
    }

    public List<ScorePoint> scoreHistory(long indicatorId, int limit) {
        return jdbc.sql("SELECT computed_at, severity, disputed FROM score WHERE indicator_id = :id "
                        + "ORDER BY computed_at DESC, id DESC LIMIT :limit")
                .param("id", indicatorId).param("limit", limit)
                .query((rs, n) -> new ScorePoint(rs.getObject("computed_at", OffsetDateTime.class), rs.getInt("severity"),
                        rs.getBoolean("disputed")))
                .list();
    }

    /**
     * Listado por severidad descendente con filtros opcionales. Pide size + 1 filas para saber si hay más página.
     * La consulta se construye solo con los filtros presentes (valores siempre como parámetros).
     */
    public List<IndicatorRow> list(String type, String category, int minSeverity, int page, int size) {
        StringBuilder sql = new StringBuilder(
                "SELECT i.id, i.type, i.value, c.components->>'category' AS category, c.severity, c.disputed, "
                        + "c.computed_at FROM (SELECT DISTINCT ON (indicator_id) * FROM score "
                        + "ORDER BY indicator_id, computed_at DESC, id DESC) c "
                        + "JOIN indicator i ON i.id = c.indicator_id WHERE c.severity >= :min");
        if (type != null) {
            sql.append(" AND i.type = :type");
        }
        if (category != null) {
            sql.append(" AND c.components->>'category' = :category");
        }
        sql.append(" ORDER BY c.severity DESC, i.id LIMIT :limit OFFSET :offset");
        JdbcClient.StatementSpec st = jdbc.sql(sql.toString()).param("min", minSeverity)
                .param("limit", size + 1).param("offset", (long) page * size);
        if (type != null) {
            st = st.param("type", type);
        }
        if (category != null) {
            st = st.param("category", category);
        }
        return st.query((rs, n) -> new IndicatorRow(rs.getLong("id"), rs.getString("type"), rs.getString("value"),
                rs.getString("category"), rs.getInt("severity"), rs.getBoolean("disputed"),
                rs.getObject("computed_at", OffsetDateTime.class))).list();
    }

    private static List<String> textArray(ResultSet rs, String column) throws SQLException {
        Array a = rs.getArray(column);
        return a == null ? List.of() : new ArrayList<>(Arrays.asList((String[]) a.getArray()));
    }
}
