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

    public record Sighting(String source, String category, OffsetDateTime seenAt, OffsetDateTime lastConfirmedAt,
                           String status, String malwareFamily, Integer confidence, String reporter,
                           Boolean corroborated) {
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
     * se renueva su última confirmación). La severidad la calcula score.py en la siguiente ejecución horaria.
     */
    public record SightingResponse(long indicatorId, long sightingId, String type, String value, String fingerprint,
                                   boolean created, String severityStatus, Score currentScore) {
    }
}
