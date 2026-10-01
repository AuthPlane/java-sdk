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
        // The body carries the same fixed sentence the challenge does; the message
        // ("expired") reaches neither half.
        assertThat(c.jsonBody())
                .contains(
                        "\"error_description\":\"The access token is missing or not valid for this resource\"");
        assertThat(c.jsonBody()).doesNotContain("expired");
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

    @Test
    void body_neverCarriesTheExceptionMessage() {
        // The body reaches a caller who by definition has not authenticated, and
        // the SDK's messages name the failing detail — here the exact audience the
        // resource expects, which is the value a caller needs in order to go
        // request a token for it.
        FailureResponse.Challenge c =
                FailureResponse.of(
                        new InvalidClaimsException(
                                "aud mismatch: expected https://api.example.com/mcp"),
                        ChallengeOptions.empty());

        assertThat(c.jsonBody())
                .contains(
                        "\"error_description\":\"The access token is missing or not valid for this resource\"");
        assertThat(c.jsonBody()).doesNotContain("api.example.com");
        assertThat(c.wwwAuthenticate()).doesNotContain("api.example.com");
    }

    @Test
    void body_andChallenge_carryTheSameCodeAndDescription() {
        // One table, two surfaces: a client reads whichever half it finds, so they
        // must not drift.
        FailureResponse.Challenge c =
                FailureResponse.of(
                        new InsufficientScopeException("admin", List.of("read")),
                        ChallengeOptions.empty());

        assertThat(c.wwwAuthenticate()).contains("error=\"insufficient_scope\"");
        assertThat(c.jsonBody()).contains("\"error\":\"insufficient_scope\"");
        assertThat(c.wwwAuthenticate())
                .contains(
                        "error_description=\"The access token does not carry the scope this operation requires\"");
        assertThat(c.jsonBody())
                .contains(
                        "\"error_description\":\"The access token does not carry the scope this operation requires\"");
    }

    @Test
    void verboseDescription_withANullMessage_keepsBothHalvesOnTheFixedSentence() {
        // The verbose escape hatch reads error.getMessage(), which is nullable — a
        // TokenExchangeException wrapping a cause that has none reaches here. The body guarded it
        // and the challenge did not, so the header emitted error_description="" beside a body
        // carrying the fixed sentence: the one case the invariant above does not reach.
        FailureResponse.Challenge c =
                FailureResponse.of(
                        new TokenExchangeException(null, null), ChallengeOptions.empty(), true);

        String expected = WwwAuthenticate.descriptionFor("invalid_token");
        assertThat(c.wwwAuthenticate()).contains("error_description=\"" + expected + "\"");
        assertThat(c.jsonBody()).contains("\"error_description\":\"" + expected + "\"");
    }

    @Test
    void verboseDescription_restoresTheMessageOnBothHalves() {
        // The escape hatch opens both surfaces together: one that opened only the
        // header would be a way to believe the message was suppressed while the
        // body still shipped it.
        FailureResponse.Challenge c =
                FailureResponse.of(
                        new TokenExpiredException("expired"), ChallengeOptions.empty(), true);

        assertThat(c.wwwAuthenticate()).contains("error_description=\"expired\"");
        assertThat(c.jsonBody()).contains("\"error_description\":\"expired\"");
    }
}
