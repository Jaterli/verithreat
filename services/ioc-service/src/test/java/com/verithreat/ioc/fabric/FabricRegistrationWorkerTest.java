package com.verithreat.ioc.fabric;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

import com.verithreat.ioc.api.Dtos.SightingRequest;
import com.verithreat.ioc.api.Dtos.SightingResponse;
import com.verithreat.ioc.service.SightingService;

/**
 * La bandeja de salida contra un PostgreSQL real, con Fabric simulado. La revisión periódica se aplaza una hora para
 * que el test llame a processDue() cuando le toca.
 */
@SpringBootTest(properties = {"verithreat.gateway-token=", "verithreat.fabric.enabled=true",
        "verithreat.fabric.poll-interval=1h"})
@Testcontainers
class FabricRegistrationWorkerTest {

    @Container
    static final PostgreSQLContainer DB = new PostgreSQLContainer("postgres:17")
            .withDatabaseName("verithreat").withUsername("verithreat").withPassword("test")
            .withCopyFileToContainer(MountableFile.forHostPath("../../db/schema.sql"),
                    "/docker-entrypoint-initdb.d/001_schema.sql")
            .withCopyFileToContainer(MountableFile.forHostPath("../../db/migrations/002_organizations.sql"),
                    "/docker-entrypoint-initdb.d/002_organizations.sql")
            .withCopyFileToContainer(MountableFile.forHostPath("../../db/migrations/004_fabric_registration.sql"),
                    "/docker-entrypoint-initdb.d/004_fabric_registration.sql");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry r) {
        String url = DB.getJdbcUrl();
        r.add("spring.datasource.url", () -> url + (url.contains("?") ? "&" : "?") + "currentSchema=verithreat");
        r.add("spring.datasource.username", DB::getUsername);
        r.add("spring.datasource.password", DB::getPassword);
    }

    @MockitoBean
    IocRegistry registry;

    @Autowired
    FabricRegistrationWorker worker;

    @Autowired
    SightingService sightings;

    @Autowired
    JdbcClient jdbc;

    @BeforeEach
    void emptyOutbox() {
        jdbc.sql("DELETE FROM fabric_registration").update();
        reset(registry);
    }

    private SightingResponse submit(String org, String domain) {
        return sightings.submit(org, new SightingRequest("domain", domain, "c2", null, null, null, null));
    }

    private static RegistryRecord record(SightingResponse s, String msp, String hash) {
        return new RegistryRecord(hash, s.type(), s.fingerprint(), "c2", msp, Instant.parse("2026-10-28T12:00:00Z"),
                "tx-" + hash.substring(0, 8));
    }

    private Map<String, Object> row(long sightingId) {
        return jdbc.sql("SELECT status, attempts, canonical_hash, tx_id, msp_id, last_error, "
                        + "next_attempt_at > now() AS deferred FROM fabric_registration WHERE sighting_id = :id")
                .param("id", sightingId).query().singleRow();
    }

    @Test
    void registersPendingSubmission() throws Exception {
        SightingResponse s = submit("org-alpha", "registered.example");
        assertEquals("pending", s.fabricStatus());
        String hash = "a".repeat(64);
        when(registry.find("org-alpha", "domain", s.fingerprint())).thenReturn(Optional.empty());
        when(registry.register("org-alpha", "domain", s.fingerprint(), "c2")).thenReturn(record(s, "Org1MSP", hash));

        assertEquals(1, worker.processDue());

        Map<String, Object> r = row(s.sightingId());
        assertEquals("registered", r.get("status"));
        assertEquals(hash, r.get("canonical_hash"));
        assertEquals("tx-aaaaaaaa", r.get("tx_id"));
        assertEquals("Org1MSP", r.get("msp_id"));
        assertEquals(0, worker.processDue()); // nada más pendiente
        // Volver a aportarlo no crea otra entrada en la bandeja de salida
        assertEquals("registered", submit("org-alpha", "registered.example").fabricStatus());
    }

    @Test
    void adoptsRecordAlreadyOnTheLedger() throws Exception {
        SightingResponse s = submit("org-beta", "adopted.example");
        when(registry.find("org-beta", "domain", s.fingerprint()))
                .thenReturn(Optional.of(record(s, "Org2MSP", "b".repeat(64))));

        assertEquals(1, worker.processDue());

        verify(registry, never()).register(anyString(), anyString(), anyString(), anyString());
        assertEquals("registered", row(s.sightingId()).get("status"));
    }

    @Test
    void transientFailureIsRetriedLaterAndStopsTheBatch() throws Exception {
        SightingResponse first = submit("org-alpha", "down-1.example");
        SightingResponse second = submit("org-alpha", "down-2.example");
        when(registry.find(anyString(), anyString(), anyString()))
                .thenThrow(new RegistryException("UNAVAILABLE: io exception", false, null));

        assertEquals(1, worker.processDue()); // el primer fallo corta la tanda

        Map<String, Object> r = row(first.sightingId());
        assertEquals("pending", r.get("status"));
        assertEquals(1, r.get("attempts"));
        assertEquals(true, r.get("deferred"));
        assertTrue(((String) r.get("last_error")).contains("UNAVAILABLE"));
        assertEquals(0, row(second.sightingId()).get("attempts"));
    }

    @Test
    void permanentFailureIsNotRetried() throws Exception {
        SightingResponse s = submit("org-alpha", "rejected.example");
        when(registry.find(anyString(), anyString(), anyString())).thenReturn(Optional.empty());
        when(registry.register(anyString(), anyString(), anyString(), any()))
                .thenThrow(new RegistryException("RegisterIoc: chaincode response 500, unknown type", true, null));

        assertEquals(1, worker.processDue());

        Map<String, Object> r = row(s.sightingId());
        assertEquals("failed", r.get("status"));
        assertNull(r.get("canonical_hash"));
        assertEquals(0, worker.processDue());
    }

    @Test
    void retryDelayDoublesUpToTheMaximum() {
        assertEquals(Duration.ofSeconds(10), worker.retryDelay(1));
        assertEquals(Duration.ofSeconds(80), worker.retryDelay(4));
        assertEquals(Duration.ofMinutes(30), worker.retryDelay(50));
    }
}
