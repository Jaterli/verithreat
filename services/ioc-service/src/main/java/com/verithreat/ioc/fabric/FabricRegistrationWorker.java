package com.verithreat.ioc.fabric;

import java.time.Duration;
import java.time.ZoneOffset;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Envía a Fabric las aportaciones pendientes de la bandeja de salida (tabla fabric_registration, migración 004).
 *
 * <p>Cada registro se procesa en su propia transacción y se bloquea con FOR UPDATE SKIP LOCKED: dos instancias del
 * servicio no lo envían a la vez. Antes de registrar se consulta si la organización ya lo tiene en la cadena (una
 * transacción confirmada en Fabric cuya anotación en la base de datos falló): así no hay registros duplicados. Si
 * Fabric no responde, se reintenta con espera creciente y se corta la tanda hasta la siguiente revisión.
 */
@Component
@ConditionalOnProperty(prefix = "verithreat.fabric", name = "enabled", havingValue = "true")
public class FabricRegistrationWorker {

    private static final Logger log = LoggerFactory.getLogger(FabricRegistrationWorker.class);
    private static final int MAX_ERROR_LENGTH = 2_000;

    private enum Outcome { NONE_DUE, DONE, TRANSIENT_FAILURE }

    private record Pending(long id, long sightingId, String organization, String type, String fingerprint,
                           String category, int attempts) {
    }

    private final JdbcClient jdbc;
    private final TransactionTemplate tx;
    private final IocRegistry registry;
    private final FabricProperties props;

    public FabricRegistrationWorker(JdbcClient jdbc, TransactionTemplate tx, IocRegistry registry,
                                    FabricProperties props) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.registry = registry;
        this.props = props;
    }

    @Scheduled(fixedDelayString = "${verithreat.fabric.poll-interval}",
            initialDelayString = "${verithreat.fabric.poll-interval}")
    public void run() {
        processDue();
    }

    /** Procesa hasta batch-size registros vencidos. Devuelve cuántos ha intentado. */
    public int processDue() {
        int processed = 0;
        while (processed < props.batchSize()) {
            Outcome outcome = tx.execute(status -> processOne());
            if (outcome == Outcome.NONE_DUE) {
                break;
            }
            processed++;
            if (outcome == Outcome.TRANSIENT_FAILURE) {
                break; // Fabric probablemente caído: no insistir con el resto hasta la siguiente revisión
            }
        }
        return processed;
    }

    private Outcome processOne() {
        Optional<Pending> next = jdbc.sql("""
                        SELECT id, sighting_id, organization, indicator_type, indicator_fingerprint, category, attempts
                        FROM fabric_registration
                        WHERE status = 'pending' AND next_attempt_at <= now()
                        ORDER BY next_attempt_at, id
                        LIMIT 1
                        FOR UPDATE SKIP LOCKED""")
                .query((rs, n) -> new Pending(rs.getLong("id"), rs.getLong("sighting_id"), rs.getString("organization"),
                        rs.getString("indicator_type"), rs.getString("indicator_fingerprint"),
                        rs.getString("category"), rs.getInt("attempts")))
                .optional();
        if (next.isEmpty()) {
            return Outcome.NONE_DUE;
        }
        Pending p = next.get();
        try {
            Optional<RegistryRecord> existing = registry.find(p.organization(), p.type(), p.fingerprint());
            RegistryRecord r = existing.isPresent() ? existing.get()
                    : registry.register(p.organization(), p.type(), p.fingerprint(), p.category());
            jdbc.sql("""
                            UPDATE fabric_registration
                            SET status = 'registered', attempts = attempts + 1, last_error = NULL,
                                canonical_hash = :hash, tx_id = :txId, msp_id = :msp, registered_at = :at,
                                updated_at = now()
                            WHERE id = :id""")
                    .param("hash", r.canonicalHash()).param("txId", r.txId()).param("msp", r.mspId())
                    .param("at", r.registeredAt().atOffset(ZoneOffset.UTC)).param("id", p.id())
                    .update();
            log.info("sighting {} registered in Fabric by {} ({}): {}", p.sightingId(), r.mspId(),
                    existing.isPresent() ? "already on the ledger" : "tx " + r.txId(), r.canonicalHash());
            return Outcome.DONE;
        } catch (RegistryException e) {
            String error = truncate(e.getMessage());
            if (e.permanent()) {
                jdbc.sql("""
                                UPDATE fabric_registration
                                SET status = 'failed', attempts = attempts + 1, last_error = :error, updated_at = now()
                                WHERE id = :id""")
                        .param("error", error).param("id", p.id()).update();
                log.error("sighting {} rejected by Fabric, will not retry: {}", p.sightingId(), error);
                return Outcome.DONE;
            }
            Duration delay = retryDelay(p.attempts() + 1);
            jdbc.sql("""
                            UPDATE fabric_registration
                            SET attempts = attempts + 1, last_error = :error,
                                next_attempt_at = now() + make_interval(secs => CAST(:delay AS float8)), updated_at = now()
                            WHERE id = :id""")
                    .param("error", error).param("delay", delay.toSeconds()).param("id", p.id()).update();
            log.warn("sighting {} not registered in Fabric (attempt {}), retrying in {}: {}", p.sightingId(),
                    p.attempts() + 1, delay, error);
            return Outcome.TRANSIENT_FAILURE;
        }
    }

    /** retry-base, el doble en cada intento, como mucho retry-max. */
    Duration retryDelay(int attempt) {
        Duration delay = props.retryBase().multipliedBy(1L << Math.min(attempt - 1, 20));
        return delay.compareTo(props.retryMax()) > 0 ? props.retryMax() : delay;
    }

    private static String truncate(String s) {
        return s == null || s.length() <= MAX_ERROR_LENGTH ? s : s.substring(0, MAX_ERROR_LENGTH) + "…";
    }
}
