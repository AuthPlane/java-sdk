package ai.authplane.sdk.core.conformance;

import java.util.List;
import java.util.Map;

final class MarkdownSupport {

    private MarkdownSupport() {}

    static String render(Map<String, Object> payload) {
        @SuppressWarnings("unchecked")
        Map<String, Object> implementation = (Map<String, Object>) payload.get("implementation");
        @SuppressWarnings("unchecked")
        Map<String, Object> runner = (Map<String, Object>) payload.get("runner");
        @SuppressWarnings("unchecked")
        Map<String, Object> summary = (Map<String, Object>) payload.get("summary");
        @SuppressWarnings("unchecked")
        Map<String, Object> uncataloguedSummary =
                (Map<String, Object>) payload.get("uncatalogued_summary");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> cases = (List<Map<String, Object>>) payload.get("cases");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> uncataloguedTests =
                (List<Map<String, Object>>) payload.get("uncatalogued_tests");

        StringBuilder builder = new StringBuilder();
        builder.append("# Conformance Report\n\n");
        builder.append("- Catalog: `")
                .append(payload.get("catalog_id"))
                .append("` `")
                .append(payload.get("catalog_version"))
                .append("`\n");
        builder.append("- Implementation: `")
                .append(implementation.get("name"))
                .append("` `")
                .append(implementation.get("version"))
                .append("`\n");
        builder.append("- Language: `").append(implementation.get("language")).append("`\n");
        builder.append("- Generated: `").append(payload.get("generated_at")).append("`\n");
        builder.append("- Runner: `")
                .append(runner.get("tool"))
                .append("` exit status `")
                .append(runner.get("exit_status"))
                .append("`\n\n");
        builder.append("## Summary\n\n");
        appendSummary(builder, summary);
        builder.append("\n## Uncatalogued Suite Tests\n\n");
        appendSummary(builder, uncataloguedSummary);
        builder.append("\n## Cases\n\n");
        builder.append("| Case ID | Status | Coverage | Test |\n");
        builder.append("|---|---|---|---|\n");
        for (Map<String, Object> entry : cases) {
            @SuppressWarnings("unchecked")
            Map<String, Object> coverage = (Map<String, Object>) entry.get("coverage");
            builder.append("| `")
                    .append(entry.get("case_id"))
                    .append("` | `")
                    .append(entry.get("status"))
                    .append("` | `")
                    .append(coverage == null ? "full" : coverage.getOrDefault("level", "full"))
                    .append("` | `")
                    .append(entry.getOrDefault("test_id", ""))
                    .append("` |\n");
        }

        List<Map<String, Object>> failures =
                cases.stream().filter(entry -> "failed".equals(entry.get("status"))).toList();
        if (!failures.isEmpty()) {
            builder.append("\n## Failures\n\n");
            for (Map<String, Object> failureEntry : failures) {
                builder.append("### `").append(failureEntry.get("case_id")).append("`\n\n");
                @SuppressWarnings("unchecked")
                Map<String, Object> failure = (Map<String, Object>) failureEntry.get("failure");
                builder.append("- Type: ").append(failure.getOrDefault("type", "")).append("\n");
                builder.append("- Message: ")
                        .append(failure.getOrDefault("message", ""))
                        .append("\n");
                @SuppressWarnings("unchecked")
                List<String> stacktrace = (List<String>) failure.get("stacktrace");
                if (stacktrace != null && !stacktrace.isEmpty()) {
                    builder.append("\n```text\n");
                    for (String line : stacktrace) {
                        builder.append(line).append("\n");
                    }
                    builder.append("```\n\n");
                }
            }
        }

        List<Map<String, Object>> annotatedCases =
                cases.stream().filter(entry -> entry.containsKey("coverage")).toList();
        if (!annotatedCases.isEmpty()) {
            builder.append("\n## Coverage Notes\n\n");
            for (Map<String, Object> entry : annotatedCases) {
                @SuppressWarnings("unchecked")
                Map<String, Object> coverage = (Map<String, Object>) entry.get("coverage");
                builder.append("### `").append(entry.get("case_id")).append("`\n\n");
                builder.append("- Coverage: `")
                        .append(coverage.getOrDefault("level", "full"))
                        .append("`\n");
                @SuppressWarnings("unchecked")
                List<String> gaps = (List<String>) coverage.get("gaps");
                if (gaps != null && !gaps.isEmpty()) {
                    builder.append("- Gaps: `").append(String.join("`, `", gaps)).append("`\n");
                }
                if (coverage.get("note") != null) {
                    builder.append("- Note: ").append(coverage.get("note")).append("\n");
                }
                builder.append("\n");
            }
        }

        if (!uncataloguedTests.isEmpty()) {
            builder.append("## Uncatalogued Test Details\n\n");
            builder.append("| Test | Status |\n");
            builder.append("|---|---|\n");
            for (Map<String, Object> entry : uncataloguedTests) {
                builder.append("| `")
                        .append(entry.get("test_id"))
                        .append("` | `")
                        .append(entry.get("status"))
                        .append("` |\n");
            }
        }

        return builder.toString();
    }

    private static void appendSummary(StringBuilder builder, Map<String, Object> summary) {
        builder.append("- Total: `").append(summary.get("total")).append("`\n");
        builder.append("- Passed: `").append(summary.get("passed")).append("`\n");
        builder.append("- Failed: `").append(summary.get("failed")).append("`\n");
        builder.append("- Skipped: `").append(summary.get("skipped")).append("`\n");
        builder.append("- Not run: `").append(summary.get("not_run")).append("`\n");
    }
}
