package com.verithreat.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;

/**
 * El Gateway contra un PostgreSQL real (esquema y migraciones de db/) y un servicio de destino simulado que registra
 * las cabeceras que le llegan.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"verithreat.gateway-token=test-gateway-token", "verithreat.api-key-cache-seconds=0"})
@Testcontainers
class GatewayIntegrationTest {

    @Container
    static final PostgreSQLContainer DB = new PostgreSQLContainer("postgres:17")
            .withDatabaseName("verithreat").withUsername("verithreat").withPassword("test")
            .withCopyFileToContainer(MountableFile.forHostPath("../../db/schema.sql"),
                    "/docker-entrypoint-initdb.d/001_schema.sql")
            .withCopyFileToContainer(MountableFile.forHostPath("../../db/migrations/002_organizations.sql"),
                    "/docker-entrypoint-initdb.d/002_organizations.sql")
            .withCopyFileToContainer(MountableFile.forHostPath("../../db/migrations/003_api_keys.sql"),
                    "/docker-entrypoint-initdb.d/003_api_keys.sql");

    static HttpServer backend;
    static final AtomicReference<Headers> lastHeaders = new AtomicReference<>();
    static final AtomicReference<String> lastPath = new AtomicReference<>();

    @BeforeAll
    static void startBackend() throws IOException {
        backend = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        backend.createContext("/", exchange -> {
            lastHeaders.set(exchange.getRequestHeaders());
            lastPath.set(exchange.getRequestURI().toString());
            byte[] body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        backend.start();
    }

    @AfterAll
    static void stopBackend() {
        backend.stop(0);
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) {
        String url = DB.getJdbcUrl();
        r.add("spring.datasource.url", () -> url + (url.contains("?") ? "&" : "?") + "currentSchema=verithreat");
        r.add("spring.datasource.username", DB::getUsername);
        r.add("spring.datasource.password", DB::getPassword);
        r.add("verithreat.ioc-service-url", () -> "http://127.0.0.1:" + backend.getAddress().getPort());
    }

    @Value("${local.server.port}")
    int port;

    @Autowired
    JdbcClient jdbc;

    private final HttpClient http = HttpClient.newHttpClient();

    private HttpResponse<String> get(String path, String apiKey, String claimedOrganization) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET();
        if (apiKey != null) {
            b.header("X-API-Key", apiKey);
        }
        if (claimedOrganization != null) {
            b.header("X-Organization", claimedOrganization);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private void addKey(String organization, String key, boolean revoked) {
        jdbc.sql("INSERT INTO api_key (organization, key_sha256, label, revoked_at) VALUES (:o, :h, 'test', "
                        + (revoked ? "now()" : "NULL") + ") ON CONFLICT (key_sha256) DO NOTHING")
                .param("o", organization).param("h", ApiKeyService.sha256Hex(key)).update();
    }

    @Test
    void rejectsMissingUnknownRevokedAndNonOrganizationKeys() throws Exception {
        addKey("org-beta", "revoked-key-beta", true);
        addKey("threatfox", "key-of-a-feed-not-an-organization", false);
        lastPath.set(null);
        for (String key : new String[] {null, "", "unknown-key", "revoked-key-beta", "key-of-a-feed-not-an-organization"}) {
            HttpResponse<String> r = get("/api/v1/indicators", key, null);
            assertEquals(401, r.statusCode(), "key " + key);
            assertTrue(r.body().contains("Unauthorized"));
        }
        assertNull(lastPath.get(), "nothing must reach the service without a valid key");
    }

    @Test
    void forwardsWithTheRealOrganizationAndGatewayToken() throws Exception {
        addKey("org-alpha", "valid-key-alpha", false);
        HttpResponse<String> r = get("/api/v1/indicators/lookup?type=domain&value=evil.com", "valid-key-alpha",
                "org-beta"); // el cliente intenta hacerse pasar por otra organización
        assertEquals(200, r.statusCode());
        assertEquals("/api/v1/indicators/lookup?type=domain&value=evil.com", lastPath.get());
        Headers h = lastHeaders.get();
        assertEquals("org-alpha", h.getFirst("X-Organization"));
        assertEquals(1, h.get("X-Organization").size());
        assertEquals("test-gateway-token", h.getFirst("X-Gateway-Token"));
        assertNull(h.getFirst("X-API-Key"), "the API key must not leave the gateway");
    }
}
