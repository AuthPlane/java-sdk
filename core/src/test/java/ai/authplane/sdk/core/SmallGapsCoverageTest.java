package ai.authplane.sdk.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import ai.authplane.sdk.core.dpop.VerifiedDPoPProof;
import ai.authplane.sdk.core.fetching.FetchSettings;
import ai.authplane.sdk.core.fetching.HttpResponseData;
import ai.authplane.sdk.core.oauth.IntrospectionResponse;

/**
 * Sweeps tiny coverage gaps across several small record/value classes that each have only a few
 * uncovered defensive branches. Each gap is uninteresting alone but together pushes core past the
 * 90% instruction-coverage gate.
 */
class SmallGapsCoverageTest {

    // -----------------------------------------------------------------------
    // IntrospectionResponse — defensive null handling
    // -----------------------------------------------------------------------

    @Test
    void introspectionResponse_nullRaw_normalizesToEmptyMap() {
        IntrospectionResponse r = new IntrospectionResponse(true, null);
        assertThat(r.raw()).isEmpty();
        assertThat(r.active()).isTrue();
    }

    @Test
    void introspectionResponse_populatedRaw_defensivelyCopied() {
        java.util.HashMap<String, Object> mutable = new java.util.HashMap<>();
        mutable.put("sub", "u-1");
        IntrospectionResponse r = new IntrospectionResponse(true, mutable);
        mutable.put("sub", "tampered");
        assertThat(r.raw().get("sub")).isEqualTo("u-1");
    }

    // -----------------------------------------------------------------------
    // FetchSettings — factories cover the only branch
    // -----------------------------------------------------------------------

    @Test
    void fetchSettings_fromDevMode_falseReturnsProduction() {
        FetchSettings s = FetchSettings.fromDevMode(false);
        assertThat(s.ssrfProtection()).isTrue();
        assertThat(s.allowHttp()).isFalse();
        assertThat(s.allowLocalhost()).isFalse();
        assertThat(s.allowPrivateNetworks()).isFalse();
        assertThat(s.timeoutSeconds()).isEqualTo(10);
    }

    @Test
    void fetchSettings_fromDevMode_trueReturnsDevMode() {
        FetchSettings s = FetchSettings.fromDevMode(true);
        assertThat(s.ssrfProtection()).isTrue();
        assertThat(s.allowHttp()).isTrue();
        assertThat(s.allowLocalhost()).isTrue();
        assertThat(s.allowPrivateNetworks()).isTrue();
    }

    // -----------------------------------------------------------------------
    // VerifiedDPoPProof — defensive null handling
    // -----------------------------------------------------------------------

    @Test
    void verifiedDPoPProof_nullRaw_normalizesToEmptyMap() {
        VerifiedDPoPProof p =
                new VerifiedDPoPProof("jti-1", "POST", "https://x/y", 100L, 200L, "thumb", null);
        assertThat(p.raw()).isEmpty();
    }

    @Test
    void verifiedDPoPProof_populatedRaw_defensivelyCopied() {
        java.util.HashMap<String, Object> mutable = new java.util.HashMap<>();
        mutable.put("htm", "POST");
        VerifiedDPoPProof p =
                new VerifiedDPoPProof("jti-1", "POST", "https://x/y", 100L, null, "thumb", mutable);
        mutable.put("htm", "GET");
        assertThat(p.raw().get("htm")).isEqualTo("POST");
    }

    @Test
    void verifiedDPoPProof_nullJti_throws() {
        assertThatThrownBy(
                        () ->
                                new VerifiedDPoPProof(
                                        null, "POST", "https://x/y", 100L, null, "thumb", Map.of()))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("jti");
    }

    @Test
    void verifiedDPoPProof_nullKeyThumbprint_throws() {
        assertThatThrownBy(
                        () ->
                                new VerifiedDPoPProof(
                                        "j", "POST", "https://x/y", 100L, null, null, Map.of()))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("keyThumbprint");
    }

    // -----------------------------------------------------------------------
    // CacheKeys — package-private helpers (test must be in same package)
    // -----------------------------------------------------------------------

    @Test
    void cacheKeys_clientCredentials_stableForSameInputs() {
        String a = CacheKeys.clientCredentials(List.of("read", "write"), List.of("https://api"));
        String b = CacheKeys.clientCredentials(List.of("read", "write"), List.of("https://api"));
        assertThat(a).isEqualTo(b);
    }

    @Test
    void cacheKeys_clientCredentials_orderIndependent() {
        String a = CacheKeys.clientCredentials(List.of("read", "write"), List.of("https://api"));
        String b = CacheKeys.clientCredentials(List.of("write", "read"), List.of("https://api"));
        assertThat(a).isEqualTo(b);
    }

    @Test
    void cacheKeys_clientCredentials_nullValues_normalizesToEmpty() {
        String a = CacheKeys.clientCredentials(null, null);
        String b = CacheKeys.clientCredentials(List.of(), List.of());
        assertThat(a).isEqualTo(b);
    }

    @Test
    void cacheKeys_clientCredentials_blankValuesStripped() {
        String a = CacheKeys.clientCredentials(List.of("read", "  "), List.of("https://api", ""));
        String b = CacheKeys.clientCredentials(List.of("read"), List.of("https://api"));
        assertThat(a).isEqualTo(b);
    }

    @Test
    void cacheKeys_tokenExchange_includesActorTokenType() {
        TokenExchangeOptions withActor =
                TokenExchangeOptions.builder("subj")
                        .actorToken("actor")
                        .actorTokenType("urn:ietf:params:oauth:token-type:jwt")
                        .build();

        String key = CacheKeys.tokenExchange(withActor);
        assertThat(key).contains("actor_token_type=");
    }

    @Test
    void cacheKeys_tokenExchange_noActorTokenLeavesTypeBlank() {
        TokenExchangeOptions noActor = TokenExchangeOptions.builder("subj").build();
        String key = CacheKeys.tokenExchange(noActor);
        // actor_token_type encoded value is empty when no actor token is set
        assertThat(key).contains("actor_token=").contains("actor_token_type=");
    }

    // -----------------------------------------------------------------------
    // HttpResponseData — defensive null handling + header lookup
    // -----------------------------------------------------------------------

    @Test
    void httpResponseData_nullBody_normalizedToEmptyString() {
        HttpResponseData r = new HttpResponseData(null, Map.of());
        assertThat(r.body()).isEmpty();
    }

    @Test
    void httpResponseData_nullHeaders_normalizedToEmpty() {
        HttpResponseData r = new HttpResponseData("body", null);
        assertThat(r.headers()).isEmpty();
        assertThat(r.header("anything")).isNull();
    }

    @Test
    void httpResponseData_headerLookupIsCaseInsensitive() {
        HttpResponseData r =
                new HttpResponseData("body", Map.of("content-type", "application/json"));
        assertThat(r.header("Content-Type")).isEqualTo("application/json");
        assertThat(r.header("CONTENT-TYPE")).isEqualTo("application/json");
        assertThat(r.header("missing")).isNull();
    }
}
