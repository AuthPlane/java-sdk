package ai.authplane.sdk.core.dpop;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

/**
 * Validates inbound DPoP proofs per RFC 9449.
 *
 * <p>Performs header validation, signature verification, claim checking, access-token binding, and
 * replay detection in a single {@link #verify} call.
 */
public final class DPoPProofVerifier {

    private DPoPProofVerifier() {}

    /**
     * Verifies a DPoP proof JWT against the supplied request context and access-token binding.
     *
     * @param proof raw DPoP proof JWT string
     * @param method HTTP method of the request (e.g. "GET")
     * @param url absolute request URL
     * @param accessToken the access token whose {@code ath} hash must match
     * @param expectedJkt expected JWK thumbprint from the token's {@code cnf.jkt} claim
     * @param options validation parameters (algorithms, clock skew, replay store)
     * @return verified proof details
     */
    public static VerifiedDPoPProof verify(
            String proof,
            String method,
            String url,
            String accessToken,
            String expectedJkt,
            InboundDPoPOptions options) {

        ParsedProof parsed = parseAndValidateHeader(proof, options);
        return validateClaimsAndBinding(parsed, method, url, accessToken, expectedJkt, options);
    }

    // ------------------------------------------------------------------
    // Step 1: Parse JWT, validate header fields, verify signature
    // ------------------------------------------------------------------

    private static ParsedProof parseAndValidateHeader(String proof, InboundDPoPOptions options) {
        if (proof == null || proof.isBlank()) {
            throw new DPoPProofMissingException("DPoP proof is required");
        }

        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(proof);
        } catch (ParseException e) {
            throw new InvalidDPoPProofException("Failed to parse DPoP proof", e);
        }

        String typ =
                jwt.getHeader().getType() != null ? jwt.getHeader().getType().toString() : null;
        if (!"dpop+jwt".equals(typ)) {
            throw new InvalidDPoPProofException("DPoP proof header typ must be 'dpop+jwt'");
        }

        String alg =
                jwt.getHeader().getAlgorithm() != null
                        ? jwt.getHeader().getAlgorithm().getName()
                        : null;
        if (alg == null || !options.allowedProofAlgorithms().contains(alg)) {
            throw new InvalidDPoPProofException("Unsupported DPoP proof algorithm: " + alg);
        }

        JWK jwk = jwt.getHeader().getJWK();
        if (jwk == null) {
            throw new InvalidDPoPProofException("DPoP proof header missing public jwk");
        }
        if (jwk.isPrivate()) {
            throw new InvalidDPoPProofException(
                    "DPoP proof header jwk must not include private key material");
        }

        verifySignature(jwt, jwk, alg);

        Map<String, Object> claims;
        try {
            claims = jwt.getJWTClaimsSet().getClaims();
        } catch (ParseException e) {
            throw new InvalidDPoPProofException("Failed to decode DPoP proof claims", e);
        }

        return new ParsedProof(jwk, claims);
    }

    // ------------------------------------------------------------------
    // Step 2: Validate claims, binding, timestamps, and replay
    // ------------------------------------------------------------------

    private static VerifiedDPoPProof validateClaimsAndBinding(
            ParsedProof parsed,
            String method,
            String url,
            String accessToken,
            String expectedJkt,
            InboundDPoPOptions options) {

        Map<String, Object> claims = parsed.claims;

        String jti = getRequiredString(claims, "jti");
        String htm = getRequiredString(claims, "htm");
        String htu = getRequiredString(claims, "htu");
        long iat = getRequiredLong(claims, "iat");
        Long exp = getOptionalLong(claims, "exp");

        if (!method.equals(htm)) {
            throw new InvalidDPoPProofException("DPoP proof method mismatch");
        }

        String normalizedUrl = DPoPSupport.normalizeHtu(url);
        String normalizedHtu = DPoPSupport.normalizeHtu(htu);
        if (!normalizedUrl.equals(normalizedHtu)) {
            throw new InvalidDPoPProofException("DPoP proof URL mismatch");
        }

        validateTimestamps(iat, exp, options);
        validateAccessTokenBinding(claims, accessToken, expectedJkt);

        String proofThumbprint = computeThumbprint(parsed.jwk);
        if (!expectedJkt.equals(proofThumbprint)) {
            throw new DPoPBindingMismatchException("DPoP proof key does not match token cnf.jkt");
        }

        checkReplay(jti, iat, exp, options);

        return new VerifiedDPoPProof(jti, htm, normalizedUrl, iat, exp, proofThumbprint, claims);
    }

    private static void validateTimestamps(long iat, Long exp, InboundDPoPOptions options) {
        long now = Instant.now().getEpochSecond();
        if (iat > now + options.clockSkewSeconds()) {
            throw new InvalidDPoPProofException("DPoP proof iat is in the future");
        }
        if (iat < now - options.maxProofAgeSeconds() - options.clockSkewSeconds()) {
            throw new InvalidDPoPProofException("DPoP proof is too old");
        }
        if (exp != null && exp < now - options.clockSkewSeconds()) {
            throw new InvalidDPoPProofException("DPoP proof has expired");
        }
    }

    private static void validateAccessTokenBinding(
            Map<String, Object> claims, String accessToken, String expectedJkt) {
        String ath = getRequiredString(claims, "ath");
        if (!DPoPSupport.computeAth(accessToken).equals(ath)) {
            throw new InvalidDPoPProofException("DPoP proof ath does not match the access token");
        }
        if (expectedJkt == null || expectedJkt.isBlank()) {
            throw new DPoPBindingMismatchException(
                    "DPoP proof validation requires cnf.jkt when an access token is provided");
        }
    }

    private static String computeThumbprint(JWK jwk) {
        try {
            return jwk.toPublicJWK().computeThumbprint().toString();
        } catch (JOSEException e) {
            throw new InvalidDPoPProofException("Failed to compute DPoP proof JWK thumbprint", e);
        }
    }

    private static void checkReplay(String jti, long iat, Long exp, InboundDPoPOptions options) {
        long replayExpiry =
                exp != null
                        ? Math.min(
                                exp,
                                iat + options.maxProofAgeSeconds() + options.clockSkewSeconds())
                        : iat + options.maxProofAgeSeconds() + options.clockSkewSeconds();

        if (!options.replayStore().storeIfAbsent(jti, Instant.ofEpochSecond(replayExpiry))) {
            throw new DPoPReplayDetectedException(
                    "DPoP proof replay detected for jti '" + jti + "'");
        }
    }

    // ------------------------------------------------------------------
    // Signature verification
    // ------------------------------------------------------------------

    private static void verifySignature(SignedJWT jwt, JWK jwk, String alg) {
        try {
            JWSVerifier verifier =
                    switch (alg) {
                        case "ES256" -> {
                            if (!(jwk instanceof ECKey ecKey)) {
                                throw new InvalidDPoPProofException(
                                        "ES256 DPoP proof must use an EC key");
                            }
                            yield new ECDSAVerifier(ecKey);
                        }
                        case "RS256" -> {
                            if (!(jwk instanceof RSAKey rsaKey)) {
                                throw new InvalidDPoPProofException(
                                        "RS256 DPoP proof must use an RSA key");
                            }
                            yield new RSASSAVerifier(rsaKey);
                        }
                        default ->
                                throw new InvalidDPoPProofException(
                                        "Unsupported DPoP proof algorithm: " + alg);
                    };

            if (!jwt.verify(verifier)) {
                throw new InvalidDPoPProofException("DPoP proof signature verification failed");
            }
        } catch (JOSEException e) {
            throw new InvalidDPoPProofException("DPoP proof signature verification failed", e);
        }
    }

    // ------------------------------------------------------------------
    // Claim extraction helpers
    // ------------------------------------------------------------------

    private static String getRequiredString(Map<String, Object> claims, String key) {
        Object value = claims.get(key);
        if (!(value instanceof String stringValue) || stringValue.isBlank()) {
            throw new InvalidDPoPProofException("DPoP proof missing required claim '" + key + "'");
        }
        return stringValue;
    }

    private static long getRequiredLong(Map<String, Object> claims, String key) {
        Object value = claims.get(key);
        if (value == null) {
            throw new InvalidDPoPProofException("DPoP proof missing required claim '" + key + "'");
        }
        if (value instanceof Date date) {
            return date.getTime() / 1000;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        try {
            return Long.parseLong(value.toString());
        } catch (NumberFormatException e) {
            throw new InvalidDPoPProofException(
                    "DPoP proof claim '" + key + "' must be numeric", e);
        }
    }

    private static Long getOptionalLong(Map<String, Object> claims, String key) {
        Object value = claims.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof Date date) {
            return date.getTime() / 1000;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        try {
            return Long.parseLong(value.toString());
        } catch (NumberFormatException e) {
            throw new InvalidDPoPProofException(
                    "DPoP proof claim '" + key + "' must be numeric", e);
        }
    }

    /** Intermediate result from header parsing, before claim validation. */
    private record ParsedProof(JWK jwk, Map<String, Object> claims) {}
}
