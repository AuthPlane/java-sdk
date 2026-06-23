package ai.authplane.sdk.core.conformance;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConformanceRunStateTest {

    @TempDir Path tempDir;

    @Test
    void close_writesJsonAndMarkdownReports() throws Exception {
        Path catalogPath = tempDir.resolve("oauth-sdk-conformance-catalog.yaml");
        Files.writeString(
                catalogPath,
                """
            schema_version: "1.0"
            catalog_id: "oauth-sdk-conformance-catalog"
            catalog_version: "test-version"
            cases:
              - id: "case-a"
              - id: "case-b"
            """);

        ConformanceRunState state =
                new ConformanceRunState(
                        tempDir,
                        tempDir,
                        catalogPath,
                        "authplane-client-java-sdk",
                        "1.0.0-test",
                        "java",
                        "junit-jupiter");

        state.recordMapped(
                "case-a",
                "ai.authplane.sdk.core.conformance.ExampleConformanceTest#caseA",
                ConformanceStatus.FAILED,
                new AssertionError("boom"),
                null);
        state.recordMapped(
                "case-b",
                "ai.authplane.sdk.core.conformance.ExampleConformanceTest#caseB",
                ConformanceStatus.PASSED,
                null,
                annotatedCoverage());
        state.recordUncatalogued(
                "ai.authplane.sdk.core.conformance.HarnessSmokeTest#helper",
                ConformanceStatus.PASSED,
                null);
        state.close();

        String json = Files.readString(tempDir.resolve("conformance-report.json"));
        String markdown = Files.readString(tempDir.resolve("conformance-report.md"));

        assertThat(json).contains("\"catalog_id\":\"oauth-sdk-conformance-catalog\"");
        assertThat(json).contains("\"catalog_version\":\"test-version\"");
        assertThat(json).contains("\"case_id\":\"case-a\"");
        assertThat(json).contains("\"status\":\"failed\"");
        assertThat(json).contains("\"case_id\":\"case-b\"");
        assertThat(json).contains("\"status\":\"passed\"");
        assertThat(json).contains("\"coverage\":{\"level\":\"partial\"");
        assertThat(json).contains("\"gaps\":[\"expected.error_hint\"]");
        assertThat(json)
                .contains(
                        "\"test_id\":\"ai.authplane.sdk.core.conformance.HarnessSmokeTest#helper\"");

        assertThat(markdown).contains("# Conformance Report");
        assertThat(markdown).contains("`case-a`");
        assertThat(markdown).contains("`failed`");
        assertThat(markdown).contains("`case-b`");
        assertThat(markdown).contains("`partial`");
        assertThat(markdown).contains("## Coverage Notes");
        assertThat(markdown).contains("## Uncatalogued Test Details");
    }

    @ConformanceCoverage(
            level = ConformanceCoverageLevel.PARTIAL,
            gaps = {"expected.error_hint"},
            note =
                    "Matches reject outcome and error category, but not the catalog diagnostic hint.")
    private static void coverageFixture() {}

    private static ConformanceCoverage annotatedCoverage() throws NoSuchMethodException {
        return ConformanceRunStateTest.class
                .getDeclaredMethod("coverageFixture")
                .getAnnotation(ConformanceCoverage.class);
    }
}
