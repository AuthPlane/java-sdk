package ai.authplane.sdk.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ai.authplane.sdk.core.errors.InvalidClaimsException;
import ai.authplane.sdk.core.errors.InvalidSignatureException;
import ai.authplane.sdk.core.errors.TokenExpiredException;

/**
 * Unit tests for JwtValidator, exercising RFC 9068 verification steps directly without a live
 * network or full AuthplaneResource lifecycle.
 */
class JwtValidatorTest {

    private static TestFixtures.RSAKeyPair rsaKeys;
    private static TestFixtures.ECKeyPair ecKeys;

    @BeforeAll
    static void setUp() {
        rsaKeys = TestFixtures.generateRsaKeyPair();
        ecKeys = TestFixtures.generateEcKeyPair();
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private JwtValidator validatorWith(JwtValidator.KeyLookup keyLookup) {
        return new JwtValidator(
                TestFixtures.ISSUER,
                TestFixtures.RESOURCE,
                Set.of("RS256", "ES256"),
                30,
                keyLookup);
    }

    /** Returns the RSA public key by KID, regardless of forceRefresh. */
    private JwtValidator.KeyLookup rsaKeyLookup() {
        return (kid, forceRefresh) ->
                TestFixtures.KID.equals(kid)
                        ? Optional.of(rsaKeys.publicJwkMap())
                        : Optional.empty();
    }

    /** Returns the EC public key by KID, regardless of forceRefresh. */
    private JwtValidator.KeyLookup ecKeyLookup() {
        return (kid, forceRefresh) ->
                TestFixtures.KID.equals(kid)
                        ? Optional.of(ecKeys.publicJwkMap())
                        : Optional.empty();
    }

    /** Always returns empty — simulates no matching key in JWKS. */
    private JwtValidator.KeyLookup emptyKeyLookup() {
        return (kid, forceRefresh) -> Optional.empty();
    }

    private String validRsaToken() {
        return TestFixtures.token().rsaKey(rsaKeys).build();
    }

    /**
     * Builds a 3-part "JWT" with the given JSON header string but an invalid signature. Useful for
     * testing header-level validation that happens before signature check.
     */
    private static String fakeToken(String headerJson) {
        String header =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString("{\"iss\":\"x\"}".getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".fakesignature";
    }

    // -----------------------------------------------------------------------
    // Happy path
    // -----------------------------------------------------------------------

    @Test
    void verify_validRsaToken_returnsAllClaims() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        VerifiedClaims claims = validator.verify(validRsaToken());

        assertThat(claims.sub()).isEqualTo(TestFixtures.SUBJECT);
        assertThat(claims.clientId()).isEqualTo(TestFixtures.CLIENT_ID);
        assertThat(claims.issuer()).isEqualTo(TestFixtures.ISSUER);
        assertThat(claims.audience()).containsExactly(TestFixtures.RESOURCE);
        assertThat(claims.jti()).isEqualTo(TestFixtures.JTI);
        assertThat(claims.kid()).isEqualTo(TestFixtures.KID);
        assertThat(claims.scopes()).containsExactlyInAnyOrder("read:data", "write:data");
    }

    @Test
    void verify_validEcToken_returnsVerifiedClaims() throws Exception {
        JwtValidator validator =
                new JwtValidator(
                        TestFixtures.ISSUER,
                        TestFixtures.RESOURCE,
                        Set.of("RS256", "ES256"),
                        30,
                        ecKeyLookup());
        String ecToken = TestFixtures.token().ecKey(ecKeys).build();
        VerifiedClaims claims = validator.verify(ecToken);
        assertThat(claims.sub()).isEqualTo(TestFixtures.SUBJECT);
        assertThat(claims.kid()).isEqualTo(TestFixtures.KID);
    }

    @Test
    void verify_keyFoundOnForceRefresh_succeeds() throws Exception {
        // First lookup (no force) returns empty; second (force=true) returns key.
        JwtValidator.KeyLookup lookup =
                (kid, forceRefresh) ->
                        forceRefresh ? Optional.of(rsaKeys.publicJwkMap()) : Optional.empty();
        JwtValidator validator = validatorWith(lookup);
        VerifiedClaims claims = validator.verify(validRsaToken());
        assertThat(claims.sub()).isEqualTo(TestFixtures.SUBJECT);
    }

    @Test
    void verify_rawClaims_accessible() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        VerifiedClaims claims = validator.verify(validRsaToken());
        assertThat(claims.raw()).containsKey("iss");
        assertThat(claims.raw()).containsKey("sub");
    }

    @Test
    void verify_expiresAtAndIssuedAt_populated() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        VerifiedClaims claims = validator.verify(validRsaToken());
        assertThat(claims.expiresAt()).isGreaterThan(Instant.now().getEpochSecond());
        assertThat(claims.issuedAt()).isLessThanOrEqualTo(Instant.now().getEpochSecond());
    }

    // -----------------------------------------------------------------------
    // Null / blank token
    // -----------------------------------------------------------------------

    @Test
    void verify_nullToken_throwsInvalidClaims() {
        JwtValidator validator = validatorWith(emptyKeyLookup());
        assertThatThrownBy(() -> validator.verify(null))
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("null or blank");
    }

    @Test
    void verify_blankToken_throwsInvalidClaims() {
        JwtValidator validator = validatorWith(emptyKeyLookup());
        assertThatThrownBy(() -> validator.verify("   "))
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("null or blank");
    }

    // -----------------------------------------------------------------------
    // Malformed JWT structure
    // -----------------------------------------------------------------------

    @Test
    void verify_malformedJwt_twoParts_throwsInvalidSignature() {
        JwtValidator validator = validatorWith(emptyKeyLookup());
        assertThatThrownBy(() -> validator.verify("header.payload"))
                .isInstanceOf(InvalidSignatureException.class)
                .hasMessageContaining("3 parts");
    }

    @Test
    void verify_malformedJwt_onePart_throwsInvalidSignature() {
        JwtValidator validator = validatorWith(emptyKeyLookup());
        assertThatThrownBy(() -> validator.verify("justonepart"))
                .isInstanceOf(InvalidSignatureException.class)
                .hasMessageContaining("3 parts");
    }

    // -----------------------------------------------------------------------
    // JWT header validation
    // -----------------------------------------------------------------------

    @Test
    void verify_missingKid_throwsInvalidClaims() {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        // Header without "kid" — validation fails at step 2 (before sig check)
        String token = fakeToken("{\"alg\":\"RS256\",\"typ\":\"at+jwt\"}");
        assertThatThrownBy(() -> validator.verify(token))
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("kid");
    }

    @Test
    void verify_missingAlg_throwsInvalidClaims() {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        String token = fakeToken("{\"kid\":\"test-key-1\",\"typ\":\"at+jwt\"}");
        assertThatThrownBy(() -> validator.verify(token))
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("alg");
    }

    @Test
    void verify_algorithmNotInAllowlist_throwsInvalidClaims() {
        // Validator only allows ES256; RS256 token must be rejected at the alg check
        JwtValidator validator =
                new JwtValidator(
                        TestFixtures.ISSUER,
                        TestFixtures.RESOURCE,
                        Set.of("ES256"),
                        30,
                        rsaKeyLookup());
        assertThatThrownBy(() -> validator.verify(validRsaToken()))
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("not in the allowed list");
    }

    @Test
    void verify_wrongTypHeader_throwsInvalidClaims() {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        String token = TestFixtures.token().rsaKey(rsaKeys).typ("JWT").build();
        assertThatThrownBy(() -> validator.verify(token))
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("at+jwt");
    }

    // -----------------------------------------------------------------------
    // Key lookup
    // -----------------------------------------------------------------------

    @Test
    void verify_keyNotFoundAfterForceRefresh_throwsInvalidSignature() {
        JwtValidator validator = validatorWith(emptyKeyLookup());
        assertThatThrownBy(() -> validator.verify(validRsaToken()))
                .isInstanceOf(InvalidSignatureException.class)
                .hasMessageContaining("No key with kid");
    }

    // -----------------------------------------------------------------------
    // Claims validation
    // -----------------------------------------------------------------------

    @Test
    void verify_wrongIssuer_throwsInvalidClaims() {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        String token =
                TestFixtures.token().rsaKey(rsaKeys).issuer("https://evil.example.com").build();
        assertThatThrownBy(() -> validator.verify(token))
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("Issuer mismatch");
    }

    @Test
    void verify_wrongAudience_throwsInvalidClaims() {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        String token =
                TestFixtures.token().rsaKey(rsaKeys).audience("https://other.example.com").build();
        assertThatThrownBy(() -> validator.verify(token))
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("Audience mismatch");
    }

    @Test
    void verify_singleElementArrayAudience_accepted() throws Exception {
        // Some AS implementations (e.g. Keycloak) always encode aud as a JSON array
        // even when there is only one audience value. A single-element array should
        // be treated identically to a plain string audience.
        JwtValidator validator = validatorWith(rsaKeyLookup());
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .audienceList(List.of(TestFixtures.RESOURCE))
                        .build();
        VerifiedClaims claims = validator.verify(token);
        assertThat(claims.audience()).containsExactly(TestFixtures.RESOURCE);
    }

    @Test
    void verify_multiElementArrayAudience_withResource_accepted() throws Exception {
        // The AS may issue tokens with multiple audiences. Accept as long as our
        // configured resource is present in the list.
        JwtValidator validator = validatorWith(rsaKeyLookup());
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .audienceList(List.of(TestFixtures.RESOURCE, "https://other.example.com"))
                        .build();
        VerifiedClaims claims = validator.verify(token);
        assertThat(claims.audience())
                .containsExactlyInAnyOrder(TestFixtures.RESOURCE, "https://other.example.com");
    }

    @Test
    void verify_multiElementArrayAudience_withoutResource_rejected() {
        // Token's aud list does not include the configured resource → rejected.
        JwtValidator validator = validatorWith(rsaKeyLookup());
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .audienceList(
                                List.of("https://other.example.com", "https://third.example.com"))
                        .build();
        assertThatThrownBy(() -> validator.verify(token))
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("Audience mismatch");
    }

    @Test
    void verify_expiredToken_throwsTokenExpired() {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        String token = TestFixtures.token().rsaKey(rsaKeys).expired().build();
        assertThatThrownBy(() -> validator.verify(token)).isInstanceOf(TokenExpiredException.class);
    }

    @Test
    void verify_futureIat_throwsInvalidClaims() {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        long future = Instant.now().getEpochSecond() + 9999;
        String token = TestFixtures.token().rsaKey(rsaKeys).issuedAt(future).build();
        assertThatThrownBy(() -> validator.verify(token))
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("iat");
    }

    @Test
    void verify_nbfInFuture_throwsInvalidClaims() {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        long futureNbf = Instant.now().getEpochSecond() + 9999;
        String token = TestFixtures.token().rsaKey(rsaKeys).notBefore(futureNbf).build();
        assertThatThrownBy(() -> validator.verify(token))
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("nbf");
    }

    @Test
    void verify_missingClientId_throwsInvalidClaims() {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        // clientId(null) causes the builder to omit the claim from the token
        String token = TestFixtures.token().rsaKey(rsaKeys).clientId(null).build();
        assertThatThrownBy(() -> validator.verify(token))
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("client_id");
    }

    // -----------------------------------------------------------------------
    // Clock skew
    // -----------------------------------------------------------------------

    @Test
    void verify_slightlyExpiredToken_acceptedWithClockSkew() throws Exception {
        // Token expired 10 seconds ago, but clock skew allows 60 seconds → passes
        JwtValidator validator =
                new JwtValidator(
                        TestFixtures.ISSUER,
                        TestFixtures.RESOURCE,
                        Set.of("RS256", "ES256"),
                        60,
                        rsaKeyLookup());
        long past = Instant.now().getEpochSecond() - 10;
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .issuedAt(past - 3600)
                        .notBefore(past - 3600)
                        .expiresAt(past)
                        .build();
        VerifiedClaims claims = validator.verify(token);
        assertThat(claims.sub()).isEqualTo(TestFixtures.SUBJECT);
    }

    // -----------------------------------------------------------------------
    // Scope parsing
    // -----------------------------------------------------------------------

    @Test
    void verify_noScope_returnsEmptyList() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        // scope(null) causes TokenBuilder to omit the claim
        String token = TestFixtures.token().rsaKey(rsaKeys).scope(null).build();
        VerifiedClaims claims = validator.verify(token);
        assertThat(claims.scopes()).isEmpty();
    }

    @Test
    void verify_singleScope_returnsSingletonList() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        String token = TestFixtures.token().rsaKey(rsaKeys).scope("read:data").build();
        VerifiedClaims claims = validator.verify(token);
        assertThat(claims.scopes()).containsExactly("read:data");
    }

    @Test
    void verify_multipleScopes_parsedCorrectly() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        String token = TestFixtures.token().rsaKey(rsaKeys).scope("a b c").build();
        VerifiedClaims claims = validator.verify(token);
        assertThat(claims.scopes()).containsExactlyInAnyOrder("a", "b", "c");
    }

    // -----------------------------------------------------------------------
    // agentId claim
    // -----------------------------------------------------------------------

    @Test
    void verify_agentIdClaim_populated() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        String token = TestFixtures.token().rsaKey(rsaKeys).claim("agent_id", "agent-abc").build();
        VerifiedClaims claims = validator.verify(token);
        assertThat(claims.agentId()).isEqualTo("agent-abc");
    }

    @Test
    void verify_agentIdClaim_absent_defaultsToEmptyString() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        // Default token has no agent_id claim
        VerifiedClaims claims = validator.verify(validRsaToken());
        assertThat(claims.agentId()).isEqualTo("");
    }

    // -----------------------------------------------------------------------
    // agentChain claim
    // -----------------------------------------------------------------------

    @Test
    void verify_agentChainClaim_populated() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .claim("agent_chain", List.of("agent-1", "agent-2"))
                        .build();
        VerifiedClaims claims = validator.verify(token);
        assertThat(claims.agentChain()).containsExactly("agent-1", "agent-2");
    }

    @Test
    void verify_agentChainClaim_absent_defaultsToEmptyList() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        // Default token has no agent_chain claim
        VerifiedClaims claims = validator.verify(validRsaToken());
        assertThat(claims.agentChain()).isEmpty();
    }

    @Test
    void verify_agentChain_isUnmodifiable() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .claim("agent_chain", List.of("agent-1", "agent-2"))
                        .build();
        VerifiedClaims claims = validator.verify(token);
        assertThatThrownBy(() -> claims.agentChain().add("agent-3"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void verify_agentChainClaim_emptyArray_returnsEmptyList() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        String token = TestFixtures.token().rsaKey(rsaKeys).claim("agent_chain", List.of()).build();
        VerifiedClaims claims = validator.verify(token);
        assertThat(claims.agentChain()).isEmpty();
    }

    @Test
    void verify_agentChainClaim_nonStringElement_throwsInvalidClaims() {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        // List contains an Integer element — must be rejected
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .claim("agent_chain", List.of("agent-1", 42))
                        .build();
        assertThatThrownBy(() -> validator.verify(token))
                .isInstanceOf(InvalidClaimsException.class);
    }

    @Test
    void verify_agentIdClaim_blank_returnsEmptyString() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        // Blank agent_id is treated as absent — should default to ""
        String token = TestFixtures.token().rsaKey(rsaKeys).claim("agent_id", "   ").build();
        VerifiedClaims claims = validator.verify(token);
        assertThat(claims.agentId()).isEqualTo("");
    }

    // -----------------------------------------------------------------------
    // notBefore claim
    // -----------------------------------------------------------------------

    @Test
    void verify_notBeforeClaim_populated() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        long pastNbf = Instant.now().getEpochSecond() - 3600;
        String token = TestFixtures.token().rsaKey(rsaKeys).notBefore(pastNbf).build();
        VerifiedClaims claims = validator.verify(token);
        assertThat(claims.notBefore()).isEqualTo(pastNbf);
    }

    @Test
    void verify_notBeforeClaim_absent_defaultsToZero() throws Exception {
        JwtValidator validator = validatorWith(rsaKeyLookup());
        // omitNbf() builds a token without any nbf claim; validator must default to 0L
        String token = TestFixtures.token().rsaKey(rsaKeys).omitNbf().build();
        VerifiedClaims claims = validator.verify(token);
        assertThat(claims.notBefore()).isEqualTo(0L);
    }
}
