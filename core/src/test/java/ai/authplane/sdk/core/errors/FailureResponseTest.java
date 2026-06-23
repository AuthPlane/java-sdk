package ai.authplane.sdk.core.errors;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import ai.authplane.sdk.core.dpop.MultipleDpopProofsException;
import ai.authplane.sdk.core.errors.WwwAuthenticate.ChallengeOptions;

class FailureResponseTest {

    @Test
    void invalidToken_is401BearerInvalidToken() {
        FailureResponse.Challenge c =
                FailureResponse.of(
                        new TokenExpiredException("expired"),
                        ChallengeOptions.empty()
                                .withResourceMetadataUrl("https://r/.well-known/x"));

        assertThat(c.status()).isEqualTo(401);
        assertThat(c.wwwAuthenticate()).startsWith("Bearer ");
        assertThat(c.wwwAuthenticate()).contains("error=\"invalid_token\"");
        assertThat(c.wwwAuthenticate()).contains("resource_metadata=\"https://r/.well-known/x\"");
        assertThat(c.jsonBody()).contains("\"error\":\"invalid_token\"");
        assertThat(c.jsonBody()).contains("\"error_description\":\"expired\"");
    }

    @Test
    void insufficientScope_is403() {
        FailureResponse.Challenge c =
                FailureResponse.of(
                        new InsufficientScopeException("admin", List.of("read")),
                        ChallengeOptions.empty());

        assertThat(c.status()).isEqualTo(403);
        assertThat(c.wwwAuthenticate()).contains("error=\"insufficient_scope\"");
        assertThat(c.jsonBody()).contains("\"error\":\"insufficient_scope\"");
    }

    @Test
    void dpopProofError_usesDpopSchemeAndCode() {
        FailureResponse.Challenge c =
                FailureResponse.of(
                        new MultipleDpopProofsException("multiple DPoP headers"),
                        ChallengeOptions.empty());

        assertThat(c.status()).isEqualTo(401);
        assertThat(c.wwwAuthenticate()).startsWith("DPoP ");
        assertThat(c.wwwAuthenticate()).contains("error=\"invalid_dpop_proof\"");
        assertThat(c.jsonBody()).contains("\"error\":\"invalid_dpop_proof\"");
    }
}
