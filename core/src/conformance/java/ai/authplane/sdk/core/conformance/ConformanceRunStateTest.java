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
              - id: "case-c"
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
        state.recordMapped(
                "case-c",
                "ai.authplane.sdk.core.conformance.ExampleConformanceTest#caseC",
                ConformanceStatus.SKIPPED,
                null,
                noneCoverage());
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
        // The NONE constant's wire value, asserted end-to-end like partial's: a consciously
        // deferred case must reach the report as "none", never as an absent or partial level.
        assertThat(json).contains("\"case_id\":\"case-c\"");
        assertThat(json).contains("\"status\":\"skipped\"");
        assertThat(json).contains("\"coverage\":{\"level\":\"none\"");
        assertThat(json).contains("\"gaps\":[\"expected.error_hint\"]");
        assertThat(json)
                .contains(
                        "\"test_id\":\"ai.authplane.sdk.core.conformance.HarnessSmokeTest#helper\"");

        assertThat(markdown).contains("# Conformance Report");
        assertThat(markdown).contains("`case-a`");
        assertThat(markdown).contains("`failed`");
        assertThat(markdown).contains("`case-b`");
        assertThat(markdown).contains("`partial`");
        assertThat(markdown).contains("`none`");
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

    @ConformanceCoverage(
            level = ConformanceCoverageLevel.NONE,
            note = "Deferred: the gate this case requires is not implemented yet.")
    private static void noneCoverageFixture() {}

    private static ConformanceCoverage noneCoverage() throws NoSuchMethodException {
        return ConformanceRunStateTest.class
                .getDeclaredMethod("noneCoverageFixture")
                .getAnnotation(ConformanceCoverage.class);
    }
}
