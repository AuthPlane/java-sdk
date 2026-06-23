package ai.authplane.sdk.core.conformance;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Minimal parser for the shared YAML conformance catalog metadata. */
final class ConformanceCatalog {

    private static final Pattern CATALOG_ID_PATTERN =
            Pattern.compile("(?m)^catalog_id:\\s*\"([^\"]+)\"\\s*$");
    private static final Pattern CATALOG_VERSION_PATTERN =
            Pattern.compile("(?m)^catalog_version:\\s*\"([^\"]+)\"\\s*$");
    private static final Pattern CASE_ID_PATTERN =
            Pattern.compile("(?m)^\\s+- id:\\s*\"([^\"]+)\"\\s*$");

    private final String catalogId;
    private final String catalogVersion;
    private final List<String> caseIds;

    private ConformanceCatalog(String catalogId, String catalogVersion, List<String> caseIds) {
        this.catalogId = catalogId;
        this.catalogVersion = catalogVersion;
        this.caseIds = List.copyOf(caseIds);
    }

    static ConformanceCatalog load(Path catalogPath) {
        try {
            String text = Files.readString(catalogPath);
            String catalogId = extractRequired(text, CATALOG_ID_PATTERN, "catalog_id", catalogPath);
            String catalogVersion =
                    extractRequired(text, CATALOG_VERSION_PATTERN, "catalog_version", catalogPath);
            List<String> caseIds = extractCaseIds(text);
            if (caseIds.isEmpty()) {
                throw new IllegalStateException(
                        "No conformance cases found in catalog: " + catalogPath);
            }
            return new ConformanceCatalog(catalogId, catalogVersion, caseIds);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read catalog: " + catalogPath, e);
        }
    }

    String catalogId() {
        return catalogId;
    }

    String catalogVersion() {
        return catalogVersion;
    }

    List<String> caseIds() {
        return caseIds;
    }

    private static String extractRequired(
            String text, Pattern pattern, String fieldName, Path catalogPath) {
        Matcher matcher = pattern.matcher(text);
        if (!matcher.find()) {
            throw new IllegalStateException("Missing " + fieldName + " in catalog: " + catalogPath);
        }
        return matcher.group(1);
    }

    private static List<String> extractCaseIds(String text) {
        int casesSectionIndex = text.indexOf("\ncases:");
        if (casesSectionIndex < 0) {
            throw new IllegalStateException("Missing cases section in conformance catalog");
        }
        String casesSection = text.substring(casesSectionIndex);
        Matcher matcher = CASE_ID_PATTERN.matcher(casesSection);
        List<String> caseIds = new ArrayList<>();
        while (matcher.find()) {
            caseIds.add(matcher.group(1));
        }
        return caseIds;
    }
}
