package ai.authplane.sdk.core;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/** Shared test fixtures: key generation and JWT signing utilities. */
public final class TestFixtures {

    // Default claims used across most tests
    public static final String ISSUER = "https://auth.example.com";
    public static final String RESOURCE = "https://api.example.com";
    public static final String SUBJECT = "user-123";
    public static final String CLIENT_ID = "client-abc";
    public static final String JTI = "unique-token-id-001";
    public static final String KID = "test-key-1";
    public static final List<String> SCOPES = List.of("read:data", "write:data");

    private TestFixtures() {}

    // -----------------------------------------------------------------------
    // Key generation
    // -----------------------------------------------------------------------

    /** Generates an RSA 2048-bit key pair with a JWKS-compatible JWK. */
    public static RSAKeyPair generateRsaKeyPair() {
        try {
            RSAKey jwk =
                    new RSAKeyGenerator(2048)
                            .keyID(KID)
                            .algorithm(JWSAlgorithm.RS256)
                            .keyUse(KeyUse.SIGNATURE)
                            .generate();
            return new RSAKeyPair(jwk);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
    }

    /** Generates an EC P-256 key pair with a JWKS-compatible JWK. */
    public static ECKeyPair generateEcKeyPair() {
        try {
            ECKey jwk =
                    new ECKeyGenerator(Curve.P_256)
                            .keyID(KID)
                            .algorithm(JWSAlgorithm.ES256)
                            .keyUse(KeyUse.SIGNATURE)
                            .generate();
            return new ECKeyPair(jwk);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate EC key pair", e);
        }
    }

    // -----------------------------------------------------------------------
    // Key pair wrappers
    // -----------------------------------------------------------------------

    public record RSAKeyPair(RSAKey jwk) {
        public RSAKey publicJwk() {
            try {
                return jwk.toPublicJWK();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public Map<String, Object> publicJwkMap() {
            return publicJwk().toJSONObject();
        }

        public Map<String, Object> jwksDocument() {
            return Map.of("keys", List.of(publicJwkMap()));
        }
    }

    public record ECKeyPair(ECKey jwk) {
        public ECKey publicJwk() {
            try {
                return jwk.toPublicJWK();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public Map<String, Object> publicJwkMap() {
            return publicJwk().toJSONObject();
        }

        public Map<String, Object> jwksDocument() {
            return Map.of("keys", List.of(publicJwkMap()));
        }
    }

    // -----------------------------------------------------------------------
    // JWT token factory
    // -----------------------------------------------------------------------

    /**
     * Builder for constructing signed JWTs with customisable claims. Call build() to get the
     * compact serialization string.
     */
    public static class TokenBuilder {

        private String issuer = ISSUER;
        private String audience = RESOURCE;
        private List<String> audienceList = null; // when non-null, forces JSON array format
        private String subject = SUBJECT;
        private String clientId = CLIENT_ID;
        private String jti = JTI;
        private String scope = "read:data write:data";
        private long issuedAt = Instant.now().getEpochSecond();
        private long notBefore = Instant.now().getEpochSecond();
        private long expiresAt = Instant.now().getEpochSecond() + 3600;
        private String typ = "at+jwt";
        private String kid = KID;
        private String alg = "RS256";
        private RSAKeyPair rsaKeyPair;
        private ECKeyPair ecKeyPair;
        private boolean omitNbf = false;

        // Extra claims for extensibility
        private final Map<String, Object> extraClaims = new LinkedHashMap<>();

        public TokenBuilder rsaKey(RSAKeyPair kp) {
            this.rsaKeyPair = kp;
            return this;
        }

        public TokenBuilder ecKey(ECKeyPair kp) {
            this.ecKeyPair = kp;
            alg = "ES256";
            return this;
        }

        public TokenBuilder issuer(String v) {
            this.issuer = v;
            return this;
        }

        public TokenBuilder audience(String v) {
            this.audience = v;
            return this;
        }

        /**
         * Forces the aud claim to be serialized as a JSON array (bypasses nimbus single-element
         * optimization).
         */
        public TokenBuilder audienceList(List<String> v) {
            this.audienceList = v;
            return this;
        }

        public TokenBuilder subject(String v) {
            this.subject = v;
            return this;
        }

        public TokenBuilder clientId(String v) {
            this.clientId = v;
            return this;
        }

        public TokenBuilder jti(String v) {
            this.jti = v;
            return this;
        }

        public TokenBuilder scope(String v) {
            this.scope = v;
            return this;
        }

        public TokenBuilder issuedAt(long v) {
            this.issuedAt = v;
            return this;
        }

        public TokenBuilder notBefore(long v) {
            this.notBefore = v;
            return this;
        }

        public TokenBuilder expiresAt(long v) {
            this.expiresAt = v;
            return this;
        }

        public TokenBuilder typ(String v) {
            this.typ = v;
            return this;
        }

        public TokenBuilder kid(String v) {
            this.kid = v;
            return this;
        }

        public TokenBuilder alg(String v) {
            this.alg = v;
            return this;
        }

        public TokenBuilder claim(String k, Object v) {
            extraClaims.put(k, v);
            return this;
        }

        /** Remove a claim by not including it (set to null to omit). */
        public TokenBuilder withoutClaim(String key) {
            extraClaims.put(key, null);
            return this;
        }

        /** Omit the {@code nbf} claim entirely from the generated token. */
        public TokenBuilder omitNbf() {
            this.omitNbf = true;
            return this;
        }

        /** Token expired 1 hour ago. */
        public TokenBuilder expired() {
            long past = Instant.now().getEpochSecond() - 7200;
            return issuedAt(past).notBefore(past).expiresAt(past + 3600);
        }

        public String build() {
            try {
                JWSAlgorithm jwsAlg = JWSAlgorithm.parse(alg);
                JWSHeader header =
                        new JWSHeader.Builder(jwsAlg)
                                .type(new JOSEObjectType(typ))
                                .keyID(kid)
                                .build();

                JWTClaimsSet.Builder claimsBuilder =
                        new JWTClaimsSet.Builder()
                                .issuer(issuer)
                                .subject(subject)
                                .jwtID(jti)
                                .issueTime(new Date(issuedAt * 1000))
                                .expirationTime(new Date(expiresAt * 1000));
                if (!omitNbf) {
                    claimsBuilder.notBeforeTime(new Date(notBefore * 1000));
                }

                // Only add client_id if non-null (null means omit the claim)
                if (clientId != null) {
                    claimsBuilder.claim("client_id", clientId);
                }
                // Only add scope if non-null
                if (scope != null) {
                    claimsBuilder.claim("scope", scope);
                }

                extraClaims.forEach(
                        (k, v) -> {
                            if (v != null) claimsBuilder.claim(k, v);
                            // null value = omit the claim
                        });

                if (audienceList != null) {
                    // Force aud as a JSON array — nimbus collapses single-element
                    // lists to a plain string, so we bypass JWTClaimsSet serialization.
                    Map<String, Object> payloadMap =
                            new LinkedHashMap<>(claimsBuilder.build().toJSONObject());
                    payloadMap.put("aud", new ArrayList<>(audienceList));
                    JWSObject jwsObject = new JWSObject(header, new Payload(payloadMap));
                    if ("RS256".equals(alg) || "RS384".equals(alg) || "RS512".equals(alg)) {
                        Objects.requireNonNull(rsaKeyPair, "RSA key pair required for " + alg);
                        jwsObject.sign(new RSASSASigner(rsaKeyPair.jwk()));
                    } else {
                        Objects.requireNonNull(ecKeyPair, "EC key pair required for " + alg);
                        jwsObject.sign(new ECDSASigner(ecKeyPair.jwk()));
                    }
                    return jwsObject.serialize();
                }

                claimsBuilder.audience(audience);
                SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());

                if ("RS256".equals(alg) || "RS384".equals(alg) || "RS512".equals(alg)) {
                    Objects.requireNonNull(rsaKeyPair, "RSA key pair required for " + alg);
                    jwt.sign(new RSASSASigner(rsaKeyPair.jwk()));
                } else if ("ES256".equals(alg) || "ES384".equals(alg) || "ES512".equals(alg)) {
                    Objects.requireNonNull(ecKeyPair, "EC key pair required for " + alg);
                    jwt.sign(new ECDSASigner(ecKeyPair.jwk()));
                } else {
                    throw new IllegalStateException("Unsupported test algorithm: " + alg);
                }

                return jwt.serialize();
            } catch (Exception e) {
                throw new RuntimeException("Failed to build test token", e);
            }
        }
    }

    public static TokenBuilder token() {
        return new TokenBuilder();
    }

    // -----------------------------------------------------------------------
    // JWKS JSON serialization (for WireMock stubs)
    // -----------------------------------------------------------------------

    public static String jwksJson(Map<String, Object> jwksDocument) {
        return serializeMap(jwksDocument);
    }

    /** Simple recursive JSON serializer for test JWKS documents. */
    public static String serializeMap(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(entry.getKey()).append("\":");
            sb.append(serializeValue(entry.getValue()));
        }
        sb.append("}");
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static String serializeValue(Object v) {
        if (v instanceof String s) return "\"" + s.replace("\"", "\\\"") + "\"";
        if (v instanceof Number) return v.toString();
        if (v instanceof Boolean) return v.toString();
        if (v instanceof List<?> list) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(serializeValue(list.get(i)));
            }
            sb.append("]");
            return sb.toString();
        }
        if (v instanceof Map<?, ?> m) return serializeMap((Map<String, Object>) m);
        return "null";
    }
}
