package com.verithreat.ioc.normalize;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Los mismos casos que ai/tests/test_normalization.py: Java y Python tienen que normalizar igual. */
class NormalizerTest {

    private static final Path CASES = Path.of("..", "..", "db", "normalization_cases.json");

    @Test
    void sharedCasesMatchPython() {
        JsonNode cases = JsonMapper.builder().build().readTree(CASES.toFile()).get("cases");
        assertFalse(cases.isEmpty(), "no cases in " + CASES.toAbsolutePath());
        List<String> failures = new ArrayList<>();
        for (JsonNode c : cases) {
            String type = c.get("type").asString();
            String input = c.get("input").asString();
            String expected = c.get("expected").isNull() ? null : c.get("expected").asString();
            String got;
            try {
                got = Normalizer.normalize(type, input);
            } catch (InvalidIndicatorException e) {
                got = null;
            }
            if (expected == null ? got != null : !expected.equals(got)) {
                failures.add(type + " '" + input + "': expected " + expected + ", got " + got);
            }
        }
        assertEquals(List.of(), failures);
    }
}
