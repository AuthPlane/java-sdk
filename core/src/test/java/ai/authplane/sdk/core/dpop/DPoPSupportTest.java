package ai.authplane.sdk.core.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/** Tests for the package-private DPoPSupport helpers. */
class DPoPSupportTest {

    // -----------------------------------------------------------------------
    // normalizeHtu
    // -----------------------------------------------------------------------

    @Test
    void normalizeHtu_keepsAbsoluteUrl_lowercaseSchemeAndHost() {
        assertThat(DPoPSupport.normalizeHtu("HTTPS://Api.Example.COM/v1/resource"))
                .isEqualTo("https://api.example.com/v1/resource");
    }

    @Test
    void normalizeHtu_stripsDefaultHttpsPort() {
        assertThat(DPoPSupport.normalizeHtu("https://api.example.com:443/r"))
                .isEqualTo("https://api.example.com/r");
    }

    @Test
    void normalizeHtu_stripsDefaultHttpPort() {
        assertThat(DPoPSupport.normalizeHtu("http://api.example.com:80/r"))
                .isEqualTo("http://api.example.com/r");
    }

    @Test
    void normalizeHtu_keepsNonDefaultPort() {
        assertThat(DPoPSupport.normalizeHtu("https://api.example.com:8443/r"))
                .isEqualTo("https://api.example.com:8443/r");
    }

    @Test
    void normalizeHtu_emptyPath_normalizesToSlash() {
        assertThat(DPoPSupport.normalizeHtu("https://api.example.com"))
                .isEqualTo("https://api.example.com/");
    }

    @Test
    void normalizeHtu_preservesPercentEncodedReservedChars() {
        // RFC 3986 §6.2.2.2: reserved chars must stay encoded — an encoded "%2F" is NOT "/".
        // The raw path is preserved (not decoded), so distinct request targets aren't conflated.
        assertThat(DPoPSupport.normalizeHtu("https://api.example.com/a%2Fb"))
                .isEqualTo("https://api.example.com/a%2Fb");
    }

    @Test
    void normalizeHtu_encodedSlashNotEqualToDecodedSlash() {
        // Binding correctness: a proof minted for "/a%2Fb" must not match a request to "/a/b".
        assertThat(DPoPSupport.normalizeHtu("https://api.example.com/a%2Fb"))
                .isNotEqualTo(DPoPSupport.normalizeHtu("https://api.example.com/a/b"));
    }

    @Test
    void normalizeHtu_missingScheme_throws() {
        assertThatThrownBy(() -> DPoPSupport.normalizeHtu("//api.example.com/r"))
                .isInstanceOf(InvalidDPoPProofException.class)
                .hasMessageContaining("absolute");
    }

    @Test
    void normalizeHtu_missingHost_throws() {
        assertThatThrownBy(() -> DPoPSupport.normalizeHtu("file:///etc/passwd"))
                .isInstanceOf(InvalidDPoPProofException.class)
                .hasMessageContaining("absolute");
    }

    @Test
    void normalizeHtu_invalidUriSyntax_throws() {
        assertThatThrownBy(() -> DPoPSupport.normalizeHtu("https://host with spaces/r"))
                .isInstanceOf(InvalidDPoPProofException.class)
                .hasMessageContaining("absolute");
    }

    // -----------------------------------------------------------------------
    // originKey
    // -----------------------------------------------------------------------

    @Test
    void originKey_httpsWithExplicitPort_keepsPort() {
        assertThat(DPoPSupport.originKey("https://api.example.com:8443/r"))
                .isEqualTo("https://api.example.com:8443");
    }

    @Test
    void originKey_httpsWithoutPort_defaultsTo443() {
        assertThat(DPoPSupport.originKey("https://api.example.com/r"))
                .isEqualTo("https://api.example.com:443");
    }

    @Test
    void originKey_httpWithoutPort_defaultsTo80() {
        assertThat(DPoPSupport.originKey("http://api.example.com/r"))
                .isEqualTo("http://api.example.com:80");
    }

    @Test
    void originKey_missingScheme_throws() {
        assertThatThrownBy(() -> DPoPSupport.originKey("//api.example.com/r"))
                .isInstanceOf(InvalidDPoPProofException.class);
    }

    @Test
    void originKey_invalidUri_throws() {
        assertThatThrownBy(() -> DPoPSupport.originKey("https://host with spaces/r"))
                .isInstanceOf(InvalidDPoPProofException.class);
    }

    // -----------------------------------------------------------------------
    // computeAth (RFC 9449 §4.3 — SHA-256 over access token, base64url, no pad)
    // -----------------------------------------------------------------------

    @Test
    void computeAth_knownInput_producesBase64UrlSha256NoPadding() {
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        // → base64url (no pad): LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ
        String ath = DPoPSupport.computeAth("hello");
        assertThat(ath).isEqualTo("LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ");
    }

    @Test
    void computeAth_isStableAcrossCalls() {
        String first = DPoPSupport.computeAth("any-token");
        String second = DPoPSupport.computeAth("any-token");
        assertThat(first).isEqualTo(second);
    }

    @Test
    void computeAth_differentTokens_differentAth() {
        assertThat(DPoPSupport.computeAth("token-a"))
                .isNotEqualTo(DPoPSupport.computeAth("token-b"));
    }
}
