package ai.authplane.sdk.core.conformance;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Resolves the shared OAuth SDK conformance catalog on disk. */
final class ConformanceCatalogPaths {

    static final String CATALOG_FILE_NAME = "oauth-sdk-conformance-catalog.yaml";

    private ConformanceCatalogPaths() {}

    /**
     * Resolves the catalog path for the given SDK project root ({@code user.dir} during Maven
     * tests).
     *
     * <p>Lookup order:
     *
     * <ol>
     *   <li>{@code CONFORMANCE_CATALOG_PATH} when set (must exist)
     *   <li>{@code <module>/conformance/}{@value #CATALOG_FILE_NAME} (in-module / CI nested
     *       checkout)
     *   <li>{@code <repo-root>/conformance/}{@value #CATALOG_FILE_NAME} (sibling of the module)
     *   <li>{@code <parent>/conformance/}{@value #CATALOG_FILE_NAME} (cloned next to the SDK repo)
     * </ol>
     */
    static Path resolve(Path projectRoot) {
        projectRoot = projectRoot.toAbsolutePath().normalize();
        String env = System.getenv("CONFORMANCE_CATALOG_PATH");
        if (env != null && !env.isBlank()) {
            Path p = Path.of(env).toAbsolutePath().normalize();
            if (!Files.isRegularFile(p)) {
                throw new IllegalStateException(
                        "CONFORMANCE_CATALOG_PATH is set but is not a regular file: " + p);
            }
            return p;
        }

        List<Path> tried = new ArrayList<>();
        for (Path candidate : defaultCandidates(projectRoot)) {
            tried.add(candidate);
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }

        StringBuilder msg = new StringBuilder();
        msg.append("Conformance catalog not found. Tried:\n");
        for (Path p : tried) {
            msg.append("  - ").append(p).append('\n');
        }
        msg.append(
                "Clone https://github.com/AuthPlane/conformance next to this repo"
                        + " (see src/conformance/README.md) or set CONFORMANCE_CATALOG_PATH.");
        throw new IllegalStateException(msg.toString());
    }

    private static List<Path> defaultCandidates(Path projectRoot) {
        // The shared catalog repo is checked out *outside* this module (nesting
        // it inside the SDK tree would be messy). Resolution walks outward from
        // the module's working directory (e.g. core/) to find a sibling
        // `conformance/` checkout:
        //   <repo-root>/conformance/   (sibling of the module, at the SDK repo root)
        //   <parent>/conformance/      (cloned next to the SDK repo — see
        // src/conformance/README.md)
        // The in-module path is tried first only to cover a CI nested checkout.
        List<Path> out = new ArrayList<>(4);
        out.add(projectRoot.resolve("conformance").resolve(CATALOG_FILE_NAME));
        out.add(projectRoot.resolveSibling("conformance").resolve(CATALOG_FILE_NAME));
        Path repoParent = projectRoot.getParent();
        if (repoParent != null) {
            out.add(repoParent.resolveSibling("conformance").resolve(CATALOG_FILE_NAME));
        }
        return out;
    }
}
