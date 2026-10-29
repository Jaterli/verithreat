package com.verithreat.ioc.api;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Objetos de la API (JSON). */
public final class Dtos {

    private Dtos() {
    }

    /** Severidad actual con sus componentes (tal como los guarda score.py). */
    public record Score(int severity, boolean disputed, Double pMalicious, OffsetDateTime computedAt,
                        Map<String, Object> components) {
    }

    /** Resumen de las observaciones de un indicador (vista v_indicator). */
    public record SightingSummary(OffsetDateTime firstSeen, OffsetDateTime lastConfirmed, int sightings, int sources,
                                  int families, List<String> categories, List<String> sourceNames,
                                  Integer ipsumLevel) {
    }

    /** Respuesta de /lookup: el indicador, su severidad (null mientras no se haya puntuado) y su resumen. */
    public record IndicatorView(long id, String type, String value, String fingerprint, Score score,
                                SightingSummary summary) {
    }

    /** Fila del listado priorizado. */
    public record IndicatorRow(long id, String type, String value, String category, int severity, boolean disputed,
                               OffsetDateTime computedAt) {
    }

    public record Page<T>(List<T> items, int page, int size, boolean hasNext) {
    }

    /** Observación. {@code fabric} solo existe en las aportaciones de organizaciones (los feeds no van a Fabric). */
    public record Sighting(String source, String category, OffsetDateTime seenAt, OffsetDateTime lastConfirmedAt,
                           String status, String malwareFamily, Integer confidence, String reporter,
                           Boolean corroborated, FabricRecord fabric) {
    }

    /**
     * Registro de una aportación en Fabric: {@code status} = pending, registered o failed. Con el hash canónico y el
     * identificador de la transacción, cualquier organización del canal puede comprobarlo en la cadena.
     */
    public record FabricRecord(String status, String canonicalHash, String txId, String mspId,
                               OffsetDateTime registeredAt, int attempts) {
    }

    public record ScorePoint(OffsetDateTime computedAt, int severity, boolean disputed) {
    }

    /** Detalle de un indicador: lo de /lookup más sus observaciones y el historial de severidad. */
    public record IndicatorDetail(IndicatorView indicator, List<Sighting> sightings, List<ScorePoint> scoreHistory) {
    }

    /** Aportación de una organización. */
    public record SightingRequest(
            @NotBlank String type,
            @NotBlank @Size(max = 30_000) String value,
            @NotBlank String category,
            OffsetDateTime seenAt,
            @Size(max = 200) String malwareFamily,
            @Min(0) @Max(100) Integer confidence,
            @Size(max = 2_000) String description) {
    }

    /**
     * Resultado de una aportación. {@code created} = la organización no la había aportado antes (si ya lo había hecho,
     * se renueva su última confirmación). La severidad la calcula score.py en la siguiente ejecución horaria;
     * {@code fabricStatus} es el estado de su registro en Fabric (pending hasta que el worker lo envía).
     */
    public record SightingResponse(long indicatorId, long sightingId, String type, String value, String fingerprint,
                                   boolean created, String severityStatus, String fabricStatus, Score currentScore) {
    }

    /**
     * Panel general (GET /api/v1/stats). Las severidades son la última puntuación de cada indicador y solo se comparan
     * dentro de una categoría, por eso el histograma va por categoría.
     */
    public record Stats(OffsetDateTime generatedAt, long indicators, long scored, long disputed,
                        List<GroupStats> byTypeAndCategory, List<HistogramBin> severityHistogram,
                        List<SourceStats> sources, List<FabricStats> fabric, ModelInfo model) {
    }

    /** Severidad de un tipo dentro de una categoría: mediana y p90 exactos (como percentile_disc). */
    public record GroupStats(String type, String category, long count, long disputed, int medianSeverity,
                             int p90Severity) {
    }

    /** Tramo del histograma: severidades de {@code from} a {@code from + 9} (el último, de 90 a 100). */
    public record HistogramBin(String category, int from, long count) {
    }

    /**
     * Frescura de cada fuente. {@code lastFetchedAt} = última descarga (null en las organizaciones, que no descargan);
     * {@code activeLast48h} = observaciones confirmadas en las últimas 48 h.
     */
    public record SourceStats(String code, String family, String role, OffsetDateTime lastFetchedAt, long sightings,
                              long activeLast48h, OffsetDateTime lastConfirmedAt) {
    }

    /** Estado del registro en Fabric de las aportaciones de una organización. */
    public record FabricStats(String organization, long pending, long registered, long failed) {
    }

    /** Versión activa del modelo A con sus métricas de la evaluación temporal (null si no hay ninguna activa). */
    public record ModelInfo(String name, String version, OffsetDateTime trainedAt, Double temporalPrAuc,
                            Double temporalRocAuc) {
    }
}
