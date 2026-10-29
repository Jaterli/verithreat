package com.verithreat.ioc.repo;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.verithreat.ioc.api.Dtos.FabricStats;
import com.verithreat.ioc.api.Dtos.GroupStats;
import com.verithreat.ioc.api.Dtos.HistogramBin;
import com.verithreat.ioc.api.Dtos.ModelInfo;
import com.verithreat.ioc.api.Dtos.SourceStats;
import com.verithreat.ioc.api.Dtos.Stats;

/**
 * Agregados para el panel general. La parte cara es quedarse con la última puntuación de cada indicador (score guarda
 * el historial): se hace una sola vez, agrupando por (tipo, categoría, severidad), y la mediana, el p90 y el histograma
 * se calculan aquí a partir de esos recuentos (como mucho 7 tipos × 9 categorías × 101 severidades filas).
 */
@Repository
public class StatsRepository {

    private record Key(String type, String category) {
    }

    private record SeverityCount(Key key, int severity, long count, long disputed) {
    }

    private final JdbcClient jdbc;

    public StatsRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public Stats stats() {
        List<SeverityCount> counts = jdbc.sql("SELECT i.type, c.category, c.severity, count(*) AS n, "
                        + "count(*) FILTER (WHERE c.disputed) AS disputed "
                        + "FROM (SELECT DISTINCT ON (indicator_id) indicator_id, severity, disputed, "
                        + "components->>'category' AS category FROM score "
                        + "ORDER BY indicator_id, computed_at DESC, id DESC) c "
                        + "JOIN indicator i ON i.id = c.indicator_id GROUP BY 1, 2, 3 ORDER BY 1, 2, 3")
                .query((rs, n) -> new SeverityCount(new Key(rs.getString("type"), rs.getString("category")),
                        rs.getInt("severity"), rs.getLong("n"), rs.getLong("disputed")))
                .list();

        Map<Key, List<SeverityCount>> byKey = new LinkedHashMap<>();
        Map<String, long[]> bins = new LinkedHashMap<>();
        for (SeverityCount c : counts) {
            byKey.computeIfAbsent(c.key(), k -> new ArrayList<>()).add(c);
            bins.computeIfAbsent(c.key().category(), k -> new long[10])[Math.min(c.severity() / 10, 9)] += c.count();
        }
        List<GroupStats> groups = new ArrayList<>();
        byKey.forEach((key, rows) -> groups.add(group(key, rows)));
        groups.sort(Comparator.comparingLong(GroupStats::count).reversed());
        List<HistogramBin> histogram = new ArrayList<>();
        bins.entrySet().stream().sorted(Map.Entry.comparingByKey(Comparator.nullsLast(Comparator.naturalOrder())))
                .forEach(e -> {
                    for (int b = 0; b < 10; b++) {
                        histogram.add(new HistogramBin(e.getKey(), b * 10, e.getValue()[b]));
                    }
                });

        long indicators = jdbc.sql("SELECT count(*) FROM indicator").query(Long.class).single();
        long scored = groups.stream().mapToLong(GroupStats::count).sum();
        long disputed = groups.stream().mapToLong(GroupStats::disputed).sum();
        return new Stats(OffsetDateTime.now(ZoneOffset.UTC), indicators, scored, disputed, groups, histogram,
                sources(), fabric(), model());
    }

    /** Mediana y p90 con la definición de percentile_disc: el primer valor cuya frecuencia acumulada llega a p. */
    private static GroupStats group(Key key, List<SeverityCount> rows) {
        long total = rows.stream().mapToLong(SeverityCount::count).sum();
        long disputed = rows.stream().mapToLong(SeverityCount::disputed).sum();
        return new GroupStats(key.type(), key.category(), total, disputed, percentile(rows, total, 50),
                percentile(rows, total, 90));
    }

    private static int percentile(List<SeverityCount> rows, long total, int percent) {
        long cumulative = 0;
        for (SeverityCount r : rows) { // ordenadas por severidad ascendente
            cumulative += r.count();
            if (cumulative * 100 >= (long) percent * total) {
                return r.severity();
            }
        }
        return rows.get(rows.size() - 1).severity();
    }

    private List<SourceStats> sources() {
        return jdbc.sql("SELECT src.code, src.family, src.role, "
                        + "(SELECT max(fetched_at) FROM download d WHERE d.source = src.code) AS last_fetched, "
                        + "count(s.id) AS sightings, "
                        + "count(s.id) FILTER (WHERE s.last_confirmed_at > now() - interval '48 hours') AS active, "
                        + "max(s.last_confirmed_at) AS last_confirmed "
                        + "FROM source src LEFT JOIN sighting s ON s.source = src.code "
                        + "GROUP BY src.code ORDER BY src.role, src.code")
                .query((rs, n) -> new SourceStats(rs.getString("code"), rs.getString("family"), rs.getString("role"),
                        rs.getObject("last_fetched", OffsetDateTime.class), rs.getLong("sightings"),
                        rs.getLong("active"), rs.getObject("last_confirmed", OffsetDateTime.class)))
                .list();
    }

    private List<FabricStats> fabric() {
        return jdbc.sql("SELECT src.code, count(f.id) FILTER (WHERE f.status = 'pending') AS pending, "
                        + "count(f.id) FILTER (WHERE f.status = 'registered') AS registered, "
                        + "count(f.id) FILTER (WHERE f.status = 'failed') AS failed "
                        + "FROM source src LEFT JOIN fabric_registration f ON f.organization = src.code "
                        + "WHERE src.role = 'organization' GROUP BY src.code ORDER BY src.code")
                .query((rs, n) -> new FabricStats(rs.getString("code"), rs.getLong("pending"),
                        rs.getLong("registered"), rs.getLong("failed")))
                .list();
    }

    private ModelInfo model() {
        return jdbc.sql("SELECT name, version, trained_at, (metrics->'temporal'->>'pr_auc')::float8 AS pr_auc, "
                        + "(metrics->'temporal'->>'roc_auc')::float8 AS roc_auc "
                        + "FROM model_version WHERE active AND name = 'model_a'")
                .query((rs, n) -> new ModelInfo(rs.getString("name"), rs.getString("version"),
                        rs.getObject("trained_at", OffsetDateTime.class), (Double) rs.getObject("pr_auc", Double.class),
                        (Double) rs.getObject("roc_auc", Double.class)))
                .optional().orElse(null);
    }
}
