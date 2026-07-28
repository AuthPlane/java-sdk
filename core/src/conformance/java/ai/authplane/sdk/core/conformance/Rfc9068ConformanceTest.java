package ai.authplane.sdk.core.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.ResourceOptions;
import ai.authplane.sdk.core.TestFixtures;
import ai.authplane.sdk.core.VerifiedClaims;
import ai.authplane.sdk.core.errors.InvalidClaimsException;
import ai.authplane.sdk.core.errors.InvalidSignatureException;
import ai.authplane.sdk.core.errors.TokenExpiredException;

@ConformanceSuite
class Rfc9068ConformanceTest extends AbstractPlaceholderConformanceTest {

    private static WireMockServer wireMock;
    private static String baseUrl;
    private static TestFixtures.RSAKeyPair rsaKeys;

    @BeforeAll
    static void startWireMock() {
        rsaKeys = TestFixtures.generateRsaKeyPair();
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        baseUrl = "http://localhost:" + wireMock.port();
    }

    @AfterAll
    static void stopWireMock() {
        wireMock.stop();
    }

    @BeforeEach
    void resetStubs() {
        wireMock.resetAll();
        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl, "jwks_uri", baseUrl + "/jwks"));
        ConformanceTestSupport.stubJwks(wireMock, "/jwks", rsaKeys);
    }

    private AuthplaneResource verifier() throws Exception {
        AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl);
        return ConformanceTestSupport.buildVerifier(
                client, TestFixtures.RESOURCE, List.of("read:data"));
    }

    @Test
    @ConformanceCase("rfc9068-valid-at-jwt-must-verify")
    void rfc9068_valid_at_jwt_must_verify() {
        AuthplaneResource verifier = assertDoesNotThrow(this::verifier);
        VerifiedClaims claims =
                assertDoesNotThrow(
                        () ->
                                verifier.verify(ConformanceTestSupport.validToken(rsaKeys, baseUrl))
                                        .get()
                                        .claims());
        assertThat(claims.issuer()).isEqualTo(baseUrl);
        assertThat(claims.audience()).contains(TestFixtures.RESOURCE);
    }

    @Test
    @ConformanceCase("rfc9068-typ-must-be-at-jwt")
    void rfc9068_typ_must_be_at_jwt() {
        AuthplaneResource verifier = assertDoesNotThrow(this::verifier);
        String token = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).typ("JWT").build();

        assertThatThrownBy(() -> verifier.verify(token).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("at+jwt");
    }

    @Test
    @ConformanceCase("rfc9068-issuer-must-match")
    void rfc9068_issuer_must_match() {
        AuthplaneResource verifier = assertDoesNotThrow(this::verifier);
        String token =
                TestFixtures.token().rsaKey(rsaKeys).issuer("https://evil.example.com").build();

        assertThatThrownBy(() -> verifier.verify(token).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("Issuer mismatch");

        // Variant: a token whose iss is identical to a configured trailing-slash issuer must
        // verify — the issuer is never rewritten, end to end: discovery resolves the
        // trailing-slash well-known URL (RFC 8414 §3), the advertised issuer matches exactly
        // (§3.3), and the token's iss matches exactly (RFC 9068 §4).
        String slashIssuer = baseUrl + "/";
        wireMock.resetAll();
        ConformanceTestSupport.stubMetadataAt(
                wireMock,
                "/.well-known/oauth-authorization-server/",
                Map.of("issuer", slashIssuer, "jwks_uri", baseUrl + "/jwks"));
        ConformanceTestSupport.stubJwks(wireMock, "/jwks", rsaKeys);

        AuthplaneClient slashClient =
                assertDoesNotThrow(() -> ConformanceTestSupport.buildClient(slashIssuer));
        AuthplaneResource slashVerifier =
                ConformanceTestSupport.buildVerifier(
                        slashClient, TestFixtures.RESOURCE, List.of("read:data"));
        String acceptedToken = TestFixtures.token().rsaKey(rsaKeys).issuer(slashIssuer).build();
        VerifiedClaims claims =
                assertDoesNotThrow(() -> slashVerifier.verify(acceptedToken).get().claims());
        assertThat(claims.issuer()).isEqualTo(slashIssuer);
    }

    @Test
    @ConformanceCase("rfc9068-audience-must-match-resource")
    void rfc9068_audience_must_match_resource() {
        AuthplaneResource verifier = assertDoesNotThrow(this::verifier);
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .issuer(baseUrl)
                        .audience("https://other.example.com")
                        .build();

        assertThatThrownBy(() -> verifier.verify(token).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("Audience mismatch");
    }

    @Test
    @ConformanceCase("rfc9068-required-claims-must-be-enforced")
    void rfc9068_required_claims_missing_client_id() {
        AuthplaneResource verifier = assertDoesNotThrow(this::verifier);
        String token = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).clientId(null).build();

        assertThatThrownBy(() -> verifier.verify(token).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("client_id");
    }

    @Test
    @ConformanceCase("rfc9068-required-claims-must-be-enforced")
    void rfc9068_required_claims_missing_sub() {
        AuthplaneResource verifier = assertDoesNotThrow(this::verifier);
        String token = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).subject(null).build();

        assertThatThrownBy(() -> verifier.verify(token).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("sub");
    }

    @Test
    @ConformanceCase("rfc9068-required-claims-must-be-enforced")
    void rfc9068_required_claims_missing_iat() throws Exception {
        AuthplaneResource verifier = assertDoesNotThrow(this::verifier);
        // Build token without iat: use nimbus directly, omitting issueTime
        long now = System.currentTimeMillis() / 1000L;
        com.nimbusds.jose.JWSHeader header =
                new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                        .type(new com.nimbusds.jose.JOSEObjectType("at+jwt"))
                        .keyID(TestFixtures.KID)
                        .build();
        com.nimbusds.jwt.JWTClaimsSet claims =
                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                        .issuer(baseUrl)
                        .subject(TestFixtures.SUBJECT)
                        .audience(TestFixtures.RESOURCE)
                        .jwtID(TestFixtures.JTI)
                        .expirationTime(new java.util.Date((now + 3600) * 1000))
                        .notBeforeTime(new java.util.Date(now * 1000))
                        .claim("client_id", TestFixtures.CLIENT_ID)
                        .claim("scope", "read:data write:data")
                        .build();
        com.nimbusds.jwt.SignedJWT jwt = new com.nimbusds.jwt.SignedJWT(header, claims);
        jwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsaKeys.jwk()));
        String token = jwt.serialize();

        assertThatThrownBy(() -> verifier.verify(token).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("iat");
    }

    @Test
    @ConformanceCase("rfc9068-required-claims-must-be-enforced")
    void rfc9068_required_claims_missing_jti() {
        AuthplaneResource verifier = assertDoesNotThrow(this::verifier);
        String token = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).jti(null).build();

        assertThatThrownBy(() -> verifier.verify(token).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("jti");
    }

    @Test
    @ConformanceCase("rfc9068-token-header-must-contain-kid")
    void rfc9068_token_header_must_contain_kid() {
        AuthplaneResource verifier = assertDoesNotThrow(this::verifier);
        String token = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).kid("").build();

        assertThatThrownBy(() -> verifier.verify(token).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("kid");
    }

    @Test
    @ConformanceCase("rfc9068-iat-future-must-be-rejected-beyond-leeway")
    void rfc9068_iat_future_must_be_rejected_beyond_leeway() {
        AuthplaneResource verifier =
                assertDoesNotThrow(
                        () -> {
                            AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl);
                            return ConformanceTestSupport.buildVerifier(
                                    client,
                                    TestFixtures.RESOURCE,
                                    List.of("read:data"),
                                    ResourceOptions.builder().clockSkewSeconds(5).build());
                        });
        long now = System.currentTimeMillis() / 1000L;
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .issuer(baseUrl)
                        .issuedAt(now + 60)
                        .notBefore(now)
                        .expiresAt(now + 3600)
                        .build();

        assertThatThrownBy(() -> verifier.verify(token).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("iat");
    }

    @Test
    @ConformanceCase("rfc9068-token-header-must-contain-alg")
    void rfc9068_token_header_must_contain_alg() {
        AuthplaneResource verifier = assertDoesNotThrow(this::verifier);
        String token =
                "eyJraWQiOiJ0ZXN0LWtleS0xIiwidHlwIjoiYXQrand0In0."
                        + "eyJpc3MiOiJ4In0."
                        + "fakesignature";

        assertThatThrownBy(() -> verifier.verify(token).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("alg");
    }

    @Test
    @ConformanceCase("rfc9068-signature-failure-must-reject-token")
    void rfc9068_signature_failure_must_reject_token() {
        AuthplaneResource verifier = assertDoesNotThrow(this::verifier);
        TestFixtures.RSAKeyPair otherKeys = TestFixtures.generateRsaKeyPair();
        String token = TestFixtures.token().rsaKey(otherKeys).issuer(baseUrl).build();

        assertThatThrownBy(() -> verifier.verify(token).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(InvalidSignatureException.class);
    }

    @Test
    @ConformanceCase("rfc9068-expiration-and-clock-skew-must-be-enforced")
    void rfc9068_expiration_and_clock_skew_exp_past_beyond_skew() {
        // exp_past_beyond_skew → reject
        AuthplaneResource verifier =
                assertDoesNotThrow(
                        () -> {
                            AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl);
                            return ConformanceTestSupport.buildVerifier(
                                    client,
                                    TestFixtures.RESOURCE,
                                    List.of("read:data"),
                                    ResourceOptions.builder().clockSkewSeconds(30).build());
                        });
        long now = System.currentTimeMillis() / 1000L;
        // Token expired 60 seconds ago — beyond 30 s skew
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .issuer(baseUrl)
                        .issuedAt(now - 3660)
                        .notBefore(now - 3660)
                        .expiresAt(now - 60)
                        .build();

        assertThatThrownBy(() -> verifier.verify(token).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(TokenExpiredException.class);
    }

    @Test
    @ConformanceCase("rfc9068-expiration-and-clock-skew-must-be-enforced")
    void rfc9068_expiration_and_clock_skew_exp_past_within_skew() {
        // exp_past_within_skew → accept
        AuthplaneResource verifier =
                assertDoesNotThrow(
                        () -> {
                            AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl);
                            return ConformanceTestSupport.buildVerifier(
                                    client,
                                    TestFixtures.RESOURCE,
                                    List.of("read:data"),
                                    ResourceOptions.builder().clockSkewSeconds(30).build());
                        });
        long now = System.currentTimeMillis() / 1000L;
        // Token expired 10 seconds ago — within 30 s skew
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .issuer(baseUrl)
                        .issuedAt(now - 3610)
                        .notBefore(now - 3610)
                        .expiresAt(now - 10)
                        .build();

        VerifiedClaims claims = assertDoesNotThrow(() -> verifier.verify(token).get().claims());
        assertThat(claims.issuer()).isEqualTo(baseUrl);
    }

    @Test
    @ConformanceCase("rfc9068-expiration-and-clock-skew-must-be-enforced")
    void rfc9068_expiration_and_clock_skew_nbf_future_beyond_skew() {
        // nbf_future_beyond_skew → reject
        AuthplaneResource verifier =
                assertDoesNotThrow(
                        () -> {
                            AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl);
                            return ConformanceTestSupport.buildVerifier(
                                    client,
                                    TestFixtures.RESOURCE,
                                    List.of("read:data"),
                                    ResourceOptions.builder().clockSkewSeconds(30).build());
                        });
        long now = System.currentTimeMillis() / 1000L;
        // nbf 60 seconds in the future — beyond 30 s skew
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .issuer(baseUrl)
                        .issuedAt(now)
                        .notBefore(now + 60)
                        .expiresAt(now + 3600)
                        .build();

        assertThatThrownBy(() -> verifier.verify(token).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("nbf");
    }

    @Test
    @ConformanceCase("rfc9068-expiration-and-clock-skew-must-be-enforced")
    void rfc9068_expiration_and_clock_skew_nbf_future_within_skew() {
        // nbf_future_within_skew → accept
        AuthplaneResource verifier =
                assertDoesNotThrow(
                        () -> {
                            AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl);
                            return ConformanceTestSupport.buildVerifier(
                                    client,
                                    TestFixtures.RESOURCE,
                                    List.of("read:data"),
                                    ResourceOptions.builder().clockSkewSeconds(30).build());
                        });
        long now = System.currentTimeMillis() / 1000L;
        // nbf 10 seconds in the future — within 30 s skew
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .issuer(baseUrl)
                        .issuedAt(now)
                        .notBefore(now + 10)
                        .expiresAt(now + 3600)
                        .build();

        VerifiedClaims claims = assertDoesNotThrow(() -> verifier.verify(token).get().claims());
        assertThat(claims.issuer()).isEqualTo(baseUrl);
    }

    @Test
    @ConformanceCase("rfc9068-nbf-must-be-honored-when-present")
    void rfc9068_nbf_must_be_honored_when_present() {
        long now = System.currentTimeMillis() / 1000L;

        // Sub-case 1: future nbf 300 s ahead, beyond default 30 s clock skew → reject
        AuthplaneResource defaultVerifier = assertDoesNotThrow(this::verifier);
        String tokenFutureBeyondSkew =
                TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).notBefore(now + 300).build();
        assertThatThrownBy(() -> defaultVerifier.verify(tokenFutureBeyondSkew).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(InvalidClaimsException.class)
                .hasMessageContaining("nbf");

        // Sub-case 2: future nbf 3 s ahead, within configured 5 s skew → accept
        AuthplaneResource skewVerifier =
                assertDoesNotThrow(
                        () -> {
                            AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl);
                            return ConformanceTestSupport.buildVerifier(
                                    client,
                                    TestFixtures.RESOURCE,
                                    List.of("read:data"),
                                    ResourceOptions.builder().clockSkewSeconds(5).build());
                        });
        long nowForSkewCase = System.currentTimeMillis() / 1000L;
        String tokenFutureWithinSkew =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .issuer(baseUrl)
                        .notBefore(nowForSkewCase + 3)
                        .build();
        VerifiedClaims skewClaims =
                assertDoesNotThrow(() -> skewVerifier.verify(tokenFutureWithinSkew).get().claims());
        assertThat(skewClaims.issuer()).isEqualTo(baseUrl);

        // Sub-case 3: absent nbf → accept (nbf is optional per RFC 7519 §4.1.5)
        String tokenNoNbf = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).omitNbf().build();
        VerifiedClaims noNbfClaims =
                assertDoesNotThrow(() -> defaultVerifier.verify(tokenNoNbf).get().claims());
        assertThat(noNbfClaims.issuer()).isEqualTo(baseUrl);
    }
}
