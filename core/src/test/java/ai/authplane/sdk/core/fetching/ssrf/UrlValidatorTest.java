package ai.authplane.sdk.core.fetching.ssrf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

import ai.authplane.sdk.core.fetching.FetchSettings;

/**
 * Unit tests for UrlValidator — SSRF-safe URL validation.
 *
 * <p>Tests that require real DNS resolution use localhost, which is guaranteed to resolve to
 * 127.0.0.1/::1 without external network access.
 */
class UrlValidatorTest {

    // -----------------------------------------------------------------------
    // Scheme validation
    // -----------------------------------------------------------------------

    @Test
    void validate_httpsUrl_allowed() {
        // In devMode, localhost HTTPS resolves fine with SSRF protection off
        ValidatedUrl result =
                UrlValidator.validate("https://localhost/jwks", FetchSettings.devMode());
        assertThat(result.scheme()).isEqualTo("https");
    }

    @Test
    void validate_httpInProduction_throwsSsrfException() {
        assertThatThrownBy(
                        () ->
                                UrlValidator.validate(
                                        "http://example.com/jwks", FetchSettings.production()))
                .isInstanceOf(SsrfException.class)
                .hasMessageContaining("HTTP is not allowed");
    }

    @Test
    void validate_httpInDevMode_allowed() {
        ValidatedUrl result =
                UrlValidator.validate("http://localhost:8080/jwks", FetchSettings.devMode());
        assertThat(result.scheme()).isEqualTo("http");
    }

    @Test
    void validate_ftpScheme_throwsSsrfException() {
        assertThatThrownBy(
                        () ->
                                UrlValidator.validate(
                                        "ftp://example.com/file", FetchSettings.devMode()))
                .isInstanceOf(SsrfException.class)
                .hasMessageContaining("Unsupported URL scheme");
    }

    @Test
    void validate_noScheme_throwsSsrfException() {
        assertThatThrownBy(
                        () -> UrlValidator.validate("//example.com/path", FetchSettings.devMode()))
                .isInstanceOf(SsrfException.class);
    }

    @Test
    void validate_malformedUrl_throwsSsrfException() {
        // A URL with illegal characters triggers IllegalArgumentException in URI.create()
        assertThatThrownBy(
                        () ->
                                UrlValidator.validate(
                                        "http://host with spaces/path", FetchSettings.devMode()))
                .isInstanceOf(SsrfException.class)
                .hasMessageContaining("Malformed URL");
    }

    // -----------------------------------------------------------------------
    // Hostname validation
    // -----------------------------------------------------------------------

    @Test
    void validate_emptyHostname_throwsSsrfException() {
        assertThatThrownBy(() -> UrlValidator.validate("https:///path", FetchSettings.devMode()))
                .isInstanceOf(SsrfException.class)
                .hasMessageContaining("no hostname");
    }

    @Test
    void validate_localhostInProduction_throwsSsrfException() {
        // 127.0.0.1 is loopback; blocked in production
        assertThatThrownBy(
                        () ->
                                UrlValidator.validate(
                                        "https://localhost/jwks", FetchSettings.production()))
                .isInstanceOf(SsrfException.class)
                .hasMessageContaining("SSRF blocked");
    }

    @Test
    void validate_localhostInDevMode_succeeds() {
        ValidatedUrl result =
                UrlValidator.validate("http://localhost:9090/jwks", FetchSettings.devMode());
        assertThat(result.hostname()).isEqualTo("localhost");
        assertThat(result.resolvedIps()).isNotEmpty();
    }

    // -----------------------------------------------------------------------
    // Port resolution
    // -----------------------------------------------------------------------

    @Test
    void validate_defaultHttpsPort_is443() {
        ValidatedUrl result =
                UrlValidator.validate("https://localhost/jwks", FetchSettings.devMode());
        assertThat(result.port()).isEqualTo(443);
    }

    @Test
    void validate_defaultHttpPort_is80() {
        ValidatedUrl result =
                UrlValidator.validate("http://localhost/jwks", FetchSettings.devMode());
        assertThat(result.port()).isEqualTo(80);
    }

    @Test
    void validate_explicitPort_preserved() {
        ValidatedUrl result =
                UrlValidator.validate("http://localhost:8080/jwks", FetchSettings.devMode());
        assertThat(result.port()).isEqualTo(8080);
    }

    @Test
    void validate_customHttpsPort_preserved() {
        ValidatedUrl result =
                UrlValidator.validate("https://localhost:8443/jwks", FetchSettings.devMode());
        assertThat(result.port()).isEqualTo(8443);
    }

    // -----------------------------------------------------------------------
    // Path extraction
    // -----------------------------------------------------------------------

    @Test
    void validate_pathWithSegments_preserved() {
        ValidatedUrl result =
                UrlValidator.validate("http://localhost:9000/api/v1/keys", FetchSettings.devMode());
        assertThat(result.path()).isEqualTo("/api/v1/keys");
    }

    @Test
    void validate_emptyPath_defaultsToSlash() {
        ValidatedUrl result =
                UrlValidator.validate("http://localhost:9000", FetchSettings.devMode());
        assertThat(result.path()).isEqualTo("/");
    }

    @Test
    void validate_pathWithQueryString_preserved() {
        ValidatedUrl result =
                UrlValidator.validate(
                        "http://localhost:9000/api?foo=bar&baz=qux", FetchSettings.devMode());
        assertThat(result.path()).isEqualTo("/api?foo=bar&baz=qux");
    }

    // -----------------------------------------------------------------------
    // ValidatedUrl fields
    // -----------------------------------------------------------------------

    @Test
    void validate_originalUrlPreserved() {
        String originalUrl = "http://localhost:8080/well-known/jwks";
        ValidatedUrl result = UrlValidator.validate(originalUrl, FetchSettings.devMode());
        assertThat(result.originalUrl()).isEqualTo(originalUrl);
    }

    @Test
    void validate_resolvedIpsNonEmpty() {
        ValidatedUrl result =
                UrlValidator.validate("http://localhost:8080/jwks", FetchSettings.devMode());
        assertThat(result.resolvedIps()).isNotEmpty();
    }
}
