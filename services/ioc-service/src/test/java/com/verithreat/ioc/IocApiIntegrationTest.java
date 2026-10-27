package com.verithreat.ioc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

/**
 * La API de principio a fin contra un PostgreSQL real con el esquema y las migraciones del repositorio (db/), tal
 * como los aplica docker-compose.yml.
 */
@SpringBootTest(properties = "verithreat.gateway-token=") // la API sin Gateway; el filtro tiene su propio test
@AutoConfigureMockMvc
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class IocApiIntegrationTest {

    @Container
    static final PostgreSQLContainer DB = new PostgreSQLContainer("postgres:17")
            .withDatabaseName("verithreat").withUsername("verithreat").withPassword("test")
            .withCopyFileToContainer(MountableFile.forHostPath("../../db/schema.sql"),
                    "/docker-entrypoint-initdb.d/001_schema.sql")
            .withCopyFileToContainer(MountableFile.forHostPath("../../db/migrations/002_organizations.sql"),
                    "/docker-entrypoint-initdb.d/002_organizations.sql");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry r) {
        String url = DB.getJdbcUrl();
        r.add("spring.datasource.url", () -> url + (url.contains("?") ? "&" : "?") + "currentSchema=verithreat");
        r.add("spring.datasource.username", DB::getUsername);
        r.add("spring.datasource.password", DB::getPassword);
    }

    @Autowired
    MockMvc mvc;

    @Autowired
    JdbcClient jdbc;

    private static final String BODY = """
            {"type": "domain", "value": "  Evil-Test.COM  ", "category": "phishing", "malwareFamily": "TestKit",
             "confidence": 80, "description": "seen in a phishing campaign against our users"}""";

    @Test
    @Order(1)
    void submitRequiresAKnownOrganization() throws Exception {
        mvc.perform(post("/api/v1/sightings").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/sightings").header("X-Organization", "threatfox")
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(2)
    void submitRejectsInvalidValues() throws Exception {
        mvc.perform(post("/api/v1/sightings").header("X-Organization", "org-alpha")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"type\": \"domain\", \"value\": \"http://evil.com\", \"category\": \"phishing\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Invalid indicator"));
        mvc.perform(post("/api/v1/sightings").header("X-Organization", "org-alpha")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"type\": \"domain\", \"value\": \"evil.com\", \"category\": \"nonsense\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @Order(3)
    void submitCreatesThenRefreshes() throws Exception {
        mvc.perform(post("/api/v1/sightings").header("X-Organization", "org-alpha")
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.value").value("evil-test.com"))
                .andExpect(jsonPath("$.created").value(true))
                .andExpect(jsonPath("$.severityStatus").value("pending"));
        mvc.perform(post("/api/v1/sightings").header("X-Organization", "org-alpha")
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.created").value(false));
        mvc.perform(post("/api/v1/sightings").header("X-Organization", "org-beta")
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isCreated());
    }

    @Test
    @Order(4)
    void lookupNormalizesAndShowsBothOrganizations() throws Exception {
        mvc.perform(get("/api/v1/indicators/lookup").param("type", "domain").param("value", "EVIL-test.com."))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.value").value("evil-test.com"))
                .andExpect(jsonPath("$.score").isEmpty())
                .andExpect(jsonPath("$.summary.sightings").value(2))
                .andExpect(jsonPath("$.summary.families").value(2))
                .andExpect(jsonPath("$.summary.sourceNames[0]").value("org-alpha"))
                .andExpect(jsonPath("$.summary.sourceNames[1]").value("org-beta"));
        mvc.perform(get("/api/v1/indicators/lookup").param("type", "domain").param("value", "unknown-domain.org"))
                .andExpect(status().isNotFound());
    }

    @Test
    @Order(5)
    void scoredIndicatorAppearsInListAndDetail() throws Exception {
        long id = jdbc.sql("SELECT id FROM indicator WHERE type = 'domain' AND value = 'evil-test.com'")
                .query(Long.class).single();
        // Lo que escribiría score.py en su siguiente ejecución
        jdbc.sql("INSERT INTO score (indicator_id, components, severity) VALUES (:id, CAST(:c AS jsonb), 75)")
                .param("id", id).param("c", "{\"category\": \"phishing\", \"evidence\": 0.75}").update();

        mvc.perform(get("/api/v1/indicators/lookup").param("type", "domain").param("value", "evil-test.com"))
                .andExpect(jsonPath("$.score.severity").value(75))
                .andExpect(jsonPath("$.score.components.category").value("phishing"));
        mvc.perform(get("/api/v1/indicators").param("category", "phishing").param("minSeverity", "70"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[0].value").value("evil-test.com"))
                .andExpect(jsonPath("$.items[0].severity").value(75))
                .andExpect(jsonPath("$.hasNext").value(false));
        mvc.perform(get("/api/v1/indicators/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sightings.length()").value(2))
                .andExpect(jsonPath("$.scoreHistory[0].severity").value(75));
        mvc.perform(get("/api/v1/indicators").param("type", "nonsense"))
                .andExpect(status().isBadRequest());
    }
}
