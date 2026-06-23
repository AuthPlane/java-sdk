package ai.authplane.sdk.core.conformance;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.extension.ExtensionContext;

/** Suite-scoped state for conformance test execution and report generation. */
final class ConformanceRunState implements ExtensionContext.Store.CloseableResource {

    private static final Pattern ARTIFACT_ID_PATTERN =
            Pattern.compile("(?s)<artifactId>([^<]+)</artifactId>");
    private static final Pattern VERSION_PATTERN =
            Pattern.compile("(?s)<version>([^<]+)</version>");

    private final Path projectRoot;
    private final Path reportJsonPath;
    private final Path reportMarkdownPath;
    private final String implementationName;
    private final String implementationVersion;
    private final String language;
    private final String runnerTool;
    private final ConformanceCatalog catalog;
    private final Map<String, CaseResult> caseResults = new LinkedHashMap<>();
    private final Map<String, TestResult> uncataloguedResults = new LinkedHashMap<>();

    ConformanceRunState(
            Path projectRoot,
            Path reportDir,
            Path catalogPath,
            String implementationName,
            String implementationVersion,
            String language,
            String runnerTool) {
        this.projectRoot = Objects.requireNonNull(projectRoot, "projectRoot");
        Path resolvedReportDir = Objects.requireNonNull(reportDir, "reportDir");
        this.reportJsonPath = resolvedReportDir.resolve("conformance-report.json");
        this.reportMarkdownPath = resolvedReportDir.resolve("conformance-report.md");
        this.implementationName = Objects.requireNonNull(implementationName, "implementationName");
        this.implementationVersion =
                Objects.requireNonNull(implementationVersion, "implementationVersion");
        this.language = Objects.requireNonNull(language, "language");
        this.runnerTool = Objects.requireNonNull(runnerTool, "runnerTool");
        this.catalog = ConformanceCatalog.load(Objects.requireNonNull(catalogPath, "catalogPath"));
    }

    static ConformanceRunState createDefault() {
        Path projectRoot = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        // Reports are emitted to `conformance.report.dir` if set (CI sets it
        // to the repo root so reports surface alongside CHANGELOG, README).
        // Falls back to projectRoot for local one-off runs.
        Path reportDir =
                Path.of(System.getProperty("conformance.report.dir", projectRoot.toString()))
                        .toAbsolutePath()
                        .normalize();
        Path pomPath = projectRoot.resolve("pom.xml");
        String pomText;
        try {
            pomText = Files.readString(pomPath);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read pom.xml from " + pomPath, e);
        }
        String implementationName = extractPomField(pomText, ARTIFACT_ID_PATTERN, "artifactId");
        String implementationVersion = extractPomField(pomText, VERSION_PATTERN, "version");
        Path catalogPath = ConformanceCatalogPaths.resolve(projectRoot);
        return new ConformanceRunState(
                projectRoot,
                reportDir,
                catalogPath,
                implementationName,
                implementationVersion,
                "java",
                "maven-surefire-junit5");
    }

    void recordMapped(
            String caseId,
            String testId,
            ConformanceStatus status,
            Throwable failure,
            ConformanceCoverage coverage) {
        CaseResult result =
                caseResults.computeIfAbsent(caseId, ignored -> new CaseResult(caseId, testId));
        result.testId = testId;
        result.status = status;
        result.failure = failure == null ? null : failureSummary(failure);
        result.coverage = coverage == null ? null : coverageSummary(coverage);
    }

    void recordUncatalogued(String testId, ConformanceStatus status, Throwable failure) {
        TestResult result =
                uncataloguedResults.computeIfAbsent(testId, ignored -> new TestResult(testId));
        result.status = status;
        result.failure = failure == null ? null : failureSummary(failure);
    }

    @Override
    public void close() {
        Map<String, Object> payload = buildPayload();
        writeReport(reportJsonPath, JsonSupport.toJson(payload) + "\n");
        writeReport(reportMarkdownPath, MarkdownSupport.render(payload));
    }

    private Map<String, Object> buildPayload() {
        List<Map<String, Object>> cases = new ArrayList<>();
        for (String caseId : catalog.caseIds()) {
            CaseResult result = caseResults.get(caseId);
            if (result == null) {
                cases.add(
                        Map.of("case_id", caseId, "status", ConformanceStatus.NOT_RUN.wireValue()));
                continue;
            }
            cases.add(result.toReportMap());
        }

        List<Map<String, Object>> uncataloguedTests = new ArrayList<>();
        for (TestResult result : uncataloguedResults.values()) {
            uncataloguedTests.add(result.toReportMap());
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("catalog_id", catalog.catalogId());
        payload.put("catalog_version", catalog.catalogVersion());
        payload.put("generated_at", OffsetDateTime.now(ZoneOffset.UTC).toString());
        payload.put(
                "implementation",
                Map.of(
                        "name", implementationName,
                        "language", language,
                        "version", implementationVersion,
                        "root", projectRoot.toString()));
        payload.put(
                "runner",
                Map.of(
                        "tool",
                        runnerTool,
                        "exit_status",
                        computeExitStatus(cases, uncataloguedTests)));
        payload.put("summary", summariseCases(cases));
        payload.put("uncatalogued_summary", summariseTests(uncataloguedTests));
        payload.put("cases", cases);
        payload.put("uncatalogued_tests", uncataloguedTests);
        return payload;
    }

    private static Map<String, Object> summariseCases(List<Map<String, Object>> cases) {
        return summarise(cases, "case_id");
    }

    private static Map<String, Object> summariseTests(List<Map<String, Object>> tests) {
        return summarise(tests, "test_id");
    }

    private static Map<String, Object> summarise(
            List<Map<String, Object>> entries, String ignoredKey) {
        int passed = 0;
        int failed = 0;
        int skipped = 0;
        int notRun = 0;
        for (Map<String, Object> entry : entries) {
            String status = (String) entry.get("status");
            switch (status) {
                case "passed" -> passed++;
                case "failed" -> failed++;
                case "skipped" -> skipped++;
                case "not_run" -> notRun++;
                default ->
                        throw new IllegalStateException(
                                "Unknown conformance status: " + status + " in " + ignoredKey);
            }
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("passed", passed);
        summary.put("failed", failed);
        summary.put("skipped", skipped);
        summary.put("not_run", notRun);
        summary.put("total", entries.size());
        return summary;
    }

    private static int computeExitStatus(
            List<Map<String, Object>> cases, List<Map<String, Object>> uncataloguedTests) {
        boolean failed = hasFailures(cases) || hasFailures(uncataloguedTests);
        return failed ? 1 : 0;
    }

    private static boolean hasFailures(List<Map<String, Object>> entries) {
        for (Map<String, Object> entry : entries) {
            if ("failed".equals(entry.get("status"))) {
                return true;
            }
        }
        return false;
    }

    private static String extractPomField(String pomText, Pattern pattern, String fieldName) {
        Matcher matcher = pattern.matcher(pomText);
        if (!matcher.find()) {
            throw new IllegalStateException("Unable to locate " + fieldName + " in pom.xml");
        }
        return matcher.group(1).trim();
    }

    private static Map<String, Object> failureSummary(Throwable failure) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("type", failure.getClass().getName());
        summary.put("message", failure.getMessage() == null ? "" : failure.getMessage());
        List<String> trace = new ArrayList<>();
        for (StackTraceElement element : failure.getStackTrace()) {
            trace.add(element.toString());
            if (trace.size() == 20) {
                break;
            }
        }
        if (!trace.isEmpty()) {
            summary.put("stacktrace", trace);
        }
        return summary;
    }

    private static Map<String, Object> coverageSummary(ConformanceCoverage coverage) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("level", coverage.level().wireValue());
        if (coverage.gaps().length > 0) {
            summary.put("gaps", List.of(coverage.gaps()));
        }
        if (!coverage.note().isBlank()) {
            summary.put("note", coverage.note());
        }
        return summary;
    }

    private static void writeReport(Path path, String content) {
        try {
            Files.writeString(path, content, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Unable to write report to " + path, e);
        }
    }

    static String testId(ExtensionContext context) {
        return context.getRequiredTestClass().getName()
                + "#"
                + context.getRequiredTestMethod().getName();
    }

    private static final class CaseResult {
        private final String caseId;
        private String testId;
        private ConformanceStatus status = ConformanceStatus.NOT_RUN;
        private Map<String, Object> failure;
        private Map<String, Object> coverage;

        private CaseResult(String caseId, String testId) {
            this.caseId = caseId;
            this.testId = testId;
        }

        private Map<String, Object> toReportMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("case_id", caseId);
            map.put("test_id", testId);
            map.put("status", status.wireValue());
            if (failure != null) {
                map.put("failure", failure);
            }
            if (coverage != null) {
                map.put("coverage", coverage);
            }
            return map;
        }
    }

    private static final class TestResult {
        private final String testId;
        private ConformanceStatus status = ConformanceStatus.NOT_RUN;
        private Map<String, Object> failure;

        private TestResult(String testId) {
            this.testId = testId;
        }

        private Map<String, Object> toReportMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("test_id", testId);
            map.put("status", status.wireValue());
            if (failure != null) {
                map.put("failure", failure);
            }
            return map;
        }
    }
}
