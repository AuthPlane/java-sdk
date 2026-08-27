package ai.authplane.sdk.core.conformance;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;

class ConformanceCatalogTest {

    private static final String NL = System.lineSeparator();

    @Test
    void load_readsCatalogMetadataAndCaseIds() {
        Path projectRoot = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        Path catalogPath = ConformanceCatalogPaths.resolve(projectRoot);

        ConformanceCatalog catalog = ConformanceCatalog.load(catalogPath);

        assertThat(catalog.catalogId()).isEqualTo("oauth-sdk-conformance-catalog");
        assertThat(catalog.catalogVersion()).isNotBlank();
        assertThat(catalog.caseIds()).isNotEmpty();
        assertThat(catalog.caseIds()).contains("rfc6749-client-credentials-success-response");
    }

    /**
     * Alignment check between the resolved catalog and the {@link ConformanceCase} mappings in the
     * suite, asserted in both directions:
     *
     * <ul>
     *   <li>every catalog case id must have a mapping — an unmapped case would otherwise surface
     *       only as {@code not_run} in the conformance report, which does not fail the run;
     *   <li>every mapped case id must exist in the catalog — an id that does not is dropped when
     *       the report is built by iterating the catalog, so the test's result never reaches the
     *       exit status.
     * </ul>
     *
     * <p>This runs unconditionally, against whichever catalog {@link ConformanceCatalogPaths}
     * resolves: the SHA pinned in {@code .conformance-catalog-ref} in PR and release CI, and the
     * catalog's unpinned tip in the scheduled drift job (which points {@code
     * CONFORMANCE_CATALOG_PATH} at its own clone). Asserting it at PR time is what makes a bump of
     * {@code .conformance-catalog-ref} safe: a bump that adds cases without SDK-side coverage turns
     * the PR red instead of merging green and publishing a report full of silent {@code not_run}
     * entries.
     */
    @Test
    void catalogCasesAndConformanceMappingsAgree() throws Exception {
        Path projectRoot = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        ConformanceCatalog catalog =
                ConformanceCatalog.load(ConformanceCatalogPaths.resolve(projectRoot));

        SuiteScan scan = scanConformanceSuites();

        // Preconditions on the scan itself. Without these, a scan that read nothing (or read only
        // part of the suite) is indistinguishable from the catalog having drifted: every case id
        // would be reported as uncovered.
        assertThat(scan.loadFailures())
                .withFailMessage(
                        "Conformance-suite scan incomplete: %d classpath entr(ies) could not be"
                                + " read, so any @ConformanceCase they declare is missing from this"
                                + " check. Fix the scan before trusting its result:%n  - %s",
                        scan.loadFailures().size(), String.join(NL + "  - ", scan.loadFailures()))
                .isEmpty();
        assertThat(scan.caseIds())
                .withFailMessage(
                        "Conformance-suite scan found no @ConformanceSuite classes on the"
                                + " classpath. The scan failed — this is not catalog drift.")
                .isNotEmpty();

        Set<String> catalogIds = new TreeSet<>(catalog.caseIds());

        List<String> uncovered =
                catalogIds.stream().filter(id -> !scan.caseIds().contains(id)).sorted().toList();
        assertThat(uncovered)
                .withFailMessage(
                        "Conformance-catalog drift: %d catalog case(s) have no @ConformanceCase"
                                + " mapping in the suite. Add SDK-side coverage for each, then bump"
                                + " .conformance-catalog-ref:%n  - %s",
                        uncovered.size(), String.join(NL + "  - ", uncovered))
                .isEmpty();

        List<String> unknown =
                scan.caseIds().stream().filter(id -> !catalogIds.contains(id)).sorted().toList();
        assertThat(unknown)
                .withFailMessage(
                        "Conformance-catalog drift: %d conformance test(s) register unknown case"
                                + " id(s) (not in catalog). Their results are dropped from the report,"
                                + " which is built by iterating the catalog. Correct the id or drop the"
                                + " @ConformanceCase annotation:%n  - %s",
                        unknown.size(), String.join(NL + "  - ", unknown))
                .isEmpty();
    }

    /** Case ids declared across the suite, plus whatever the scan could not read. */
    private record SuiteScan(TreeSet<String> caseIds, List<String> loadFailures) {}

    /**
     * Collects every {@link ConformanceCase} case id declared by a {@link ConformanceSuite} test
     * class in this package or below it. Scans the compiled conformance classes on the classpath so
     * newly added suite classes are discovered automatically (no hand-maintained registry).
     *
     * <p>Anything the scan cannot read is recorded rather than skipped: a class that fails to load,
     * or a classpath root the scan cannot walk, silently loses its mappings and would be reported
     * as catalog drift.
     */
    private static SuiteScan scanConformanceSuites() throws Exception {
        TreeSet<String> ids = new TreeSet<>();
        List<String> loadFailures = new ArrayList<>();
        String packageName = ConformanceCatalogTest.class.getPackageName();
        String packagePath = packageName.replace('.', '/');
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

        Enumeration<URL> roots = classLoader.getResources(packagePath);
        while (roots.hasMoreElements()) {
            URL root = roots.nextElement();
            if (!"file".equals(root.getProtocol())) {
                // Conformance classes compile to a directory on the test classpath. A packaged jar
                // (or any other protocol) is not expected here, and silently skipping it would
                // under-report the mappings.
                loadFailures.add(root + " (classpath root is not a directory this scan can walk)");
                continue;
            }
            Path dir = Path.of(root.toURI());
            if (!Files.isDirectory(dir)) {
                continue;
            }
            for (String className : classNamesIn(dir, packageName)) {
                Class<?> clazz;
                try {
                    clazz = Class.forName(className, false, classLoader);
                } catch (Throwable t) {
                    // NoClassDefFoundError / ExceptionInInitializerError included: a suite class
                    // that cannot be loaded loses every mapping it declares.
                    loadFailures.add(className + " -> " + t);
                    continue;
                }
                if (!clazz.isAnnotationPresent(ConformanceSuite.class)) {
                    continue;
                }
                for (Method method : clazz.getDeclaredMethods()) {
                    ConformanceCase mapping = method.getAnnotation(ConformanceCase.class);
                    if (mapping != null) {
                        ids.add(mapping.value());
                    }
                }
            }
        }
        return new SuiteScan(ids, loadFailures);
    }

    /**
     * Binary names of every {@code .class} file under {@code root}, walked recursively so a suite
     * class placed in a subpackage is still discovered. The package is derived from the file's path
     * relative to {@code root}.
     */
    private static List<String> classNamesIn(Path root, String packageName) throws Exception {
        List<String> names = new ArrayList<>();
        try (var entries = Files.walk(root)) {
            for (Path entry : (Iterable<Path>) entries::iterator) {
                if (!Files.isRegularFile(entry)) {
                    continue;
                }
                String fileName = entry.getFileName().toString();
                if (!fileName.endsWith(".class")) {
                    continue;
                }
                Path relative = root.relativize(entry);
                StringBuilder binaryName = new StringBuilder(packageName);
                for (int i = 0; i < relative.getNameCount() - 1; i++) {
                    binaryName.append('.').append(relative.getName(i));
                }
                binaryName.append('.').append(fileName, 0, fileName.length() - ".class".length());
                names.add(binaryName.toString());
            }
        }
        return names;
    }
}
