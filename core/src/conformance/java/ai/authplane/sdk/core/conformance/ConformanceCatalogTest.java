package ai.authplane.sdk.core.conformance;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;

class ConformanceCatalogTest {

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
}
