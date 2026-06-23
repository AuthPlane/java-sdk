package ai.authplane.sdk.core.conformance;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import ai.authplane.sdk.core.dpop.InvalidDPoPProofException;
import ai.authplane.sdk.core.errors.InsufficientScopeException;
import ai.authplane.sdk.core.errors.InvalidSignatureException;
import ai.authplane.sdk.core.errors.TokenExpiredException;
import ai.authplane.sdk.core.errors.WwwAuthenticate;

@ConformanceSuite
class Rfc6750ConformanceTest {

    @Test
    @ConformanceCase("rfc6750-error-response-must-map-error-codes")
    void rfc6750_error_response_must_map_error_codes() {
        // token_expired → Bearer invalid_token
        String expired = WwwAuthenticate.of(new TokenExpiredException("expired"));
        assertThat(expired).startsWith("Bearer ");
        assertThat(expired).contains("error=\"invalid_token\"");
        assertThat(expired).contains("error_description=\"expired\"");

        // invalid_signature → Bearer invalid_token
        String badSig = WwwAuthenticate.of(new InvalidSignatureException("bad sig"));
        assertThat(badSig).startsWith("Bearer ");
        assertThat(badSig).contains("error=\"invalid_token\"");

        // insufficient_scope → Bearer insufficient_scope
        String noScope =
                WwwAuthenticate.of(new InsufficientScopeException("admin", List.of("read")));
        assertThat(noScope).startsWith("Bearer ");
        assertThat(noScope).contains("error=\"insufficient_scope\"");

        // dpop_error → DPoP invalid_token
        String dpop = WwwAuthenticate.of(new InvalidDPoPProofException("bad proof"));
        assertThat(dpop).startsWith("DPoP ");
        assertThat(dpop).contains("error=\"invalid_token\"");
    }

    @Test
    @ConformanceCase("rfc6750-error-response-realm-should-be-included")
    void rfc6750_error_response_realm_should_be_included() {
        String result =
                WwwAuthenticate.of(new TokenExpiredException("expired"), "https://api.example.com");
        assertThat(result).contains("realm=\"https://api.example.com\"");
        assertThat(result).startsWith("Bearer ");
        assertThat(result).contains("error=\"invalid_token\"");

        // DPoP error with realm
        String dpop =
                WwwAuthenticate.of(
                        new InvalidDPoPProofException("dpop invalid"), "https://api.example.com");
        assertThat(dpop).startsWith("DPoP ");
        assertThat(dpop).contains("realm=\"https://api.example.com\"");
    }
}
