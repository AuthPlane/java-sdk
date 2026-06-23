package ai.authplane.sdk.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;

import ai.authplane.sdk.core.errors.AuthplaneException;
import ai.authplane.sdk.core.errors.InvalidClaimsException;
import ai.authplane.sdk.core.errors.InvalidSignatureException;
import ai.authplane.sdk.core.errors.TokenExpiredException;

/**
 * Performs the full RFC 9068 JWT verification sequence.
 *
 * <p>Encapsulates all JWT parsing and claim-checking logic, independent of cache management and
 * lifecycle concerns. This separation means the verification logic can be tested without
 * constructing a full verifier with live network dependencies.
 *
 * <p>Key lookup is abstracted via {@link KeyLookup} so that the volatile JWKS cache reference in
 * {@link AuthplaneResource} is always read fresh on each call (correct after a jwks_uri rotation),
 * without coupling this class to {@code JwksCache} directly.
 */
class JwtValidator {

    private static final Logger LOG = Logger.getLogger(JwtValidator.class.getName());

    /**
     * Abstracts JWK key lookup by kid. Implemented by a lambda in AuthplaneResource that reads the
     * volatile jwksCache on each invocation.
     */
    @FunctionalInterface
    interface KeyLookup {
        Optional<Map<String, Object>> find(String kid, boolean forceRefresh) throws Exception;
    }

    private final String issuer;
    private final String resource;
    private final Set<String> allowedAlgorithms;
    private final int clockSkewSeconds;
    private final KeyLookup keyLookup;

    JwtValidator(
            String issuer,
            String resource,
            Set<String> allowedAlgorithms,
            int clockSkewSeconds,
            KeyLookup keyLookup) {
        this.issuer = issuer;
        this.resource = resource;
        this.allowedAlgorithms = allowedAlgorithms;
        this.clockSkewSeconds = clockSkewSeconds;
        this.keyLookup = keyLookup;
    }

    /**
     * Verifies a JWT Bearer token and returns its validated claims. Times the operation and logs
     * the outcome.
     */
    VerifiedClaims verify(String token) throws Exception {
        long startNs = System.nanoTime();
        try {
            VerifiedClaims claims = doVerify(token);
            double ms = (System.nanoTime() - startNs) / 1_000_000.0;
            LOG.info(
                    String.format(
                            "Token verified successfully [issuer=%s, subject=%s, duration=%.1fms]",
                            issuer, claims.sub(), ms));
            return claims;
        } catch (AuthplaneException e) {
            double ms = (System.nanoTime() - startNs) / 1_000_000.0;
            LOG.warning(
                    String.format(
                            "Token verification failed [issuer=%s, error=%s, duration=%.1fms]",
                            issuer, e.getClass().getSimpleName(), ms));
            throw e;
        }
    }

    // -----------------------------------------------------------------------
    // RFC 9068 verification steps
    // -----------------------------------------------------------------------

    private VerifiedClaims doVerify(String token) throws Exception {
        if (token == null || token.isBlank()) {
            throw new InvalidClaimsException("Token is null or blank");
        }

        // Step 1: Decode JWT header (without verification)
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new InvalidSignatureException(
                    "Malformed JWT: expected 3 parts, got " + parts.length);
        }
        Map<String, Object> header = decodeJsonSegment(parts[0], "header");

        // Steps 2–4: Validate header fields (kid, alg, typ)
        String kid = validateHeader(header);
        String alg = getRequiredStringClaim(header, "alg", true);

        // Step 5: JWKS key lookup
        Optional<Map<String, Object>> keyOpt = keyLookup.find(kid, false);
        if (keyOpt.isEmpty()) {
            LOG.info(() -> "kid '" + kid + "' not in JWKS cache, forcing refresh");
            keyOpt = keyLookup.find(kid, true);
        }
        if (keyOpt.isEmpty()) {
            throw new InvalidSignatureException(
                    "No key with kid='" + kid + "' found in JWKS (after refresh)");
        }

        // Step 6: Verify signature using nimbus-jose-jwt
        verifySignature(token, keyOpt.get(), alg);

        // Steps 7–10: Validate claims and build result
        Map<String, Object> payload = decodeJsonSegment(parts[1], "payload");
        validateClaims(payload);
        return buildVerifiedClaims(payload, kid);
    }

    /** Validates kid, alg, and typ header fields. Returns the kid. */
    private String validateHeader(Map<String, Object> header) {
        String kid = getRequiredStringClaim(header, "kid", true);

        String alg = getRequiredStringClaim(header, "alg", true);
        if (!allowedAlgorithms.contains(alg)) {
            throw new InvalidClaimsException(
                    "Algorithm '" + alg + "' is not in the allowed list " + allowedAlgorithms);
        }

        Object typObj = header.get("typ");
        String typ = typObj instanceof String s ? s : null;
        if (!"at+jwt".equals(typ)) {
            throw new InvalidClaimsException(
                    "JWT 'typ' header must be 'at+jwt' (RFC 9068), got: " + typ);
        }
        return kid;
    }

    private static VerifiedClaims buildVerifiedClaims(Map<String, Object> payload, String kid) {
        String iss = getRequiredStringClaim(payload, "iss", false);
        List<String> aud = extractAudience(payload);
        String sub = getRequiredStringClaim(payload, "sub", false);
        String clientId = getRequiredStringClaim(payload, "client_id", false);
        String jti = getRequiredStringClaim(payload, "jti", false);
        long exp = getRequiredLongClaim(payload, "exp");
        long iat = getRequiredLongClaim(payload, "iat");
        List<String> tokenScopes = parseScopes(payload);
        String agentId = getOptionalStringClaim(payload, "agent_id");
        List<String> agentChain = extractAgentChain(payload);
        Long nbfLong = getOptionalLongClaim(payload, "nbf");
        long notBefore = nbfLong != null ? nbfLong : 0L;

        return new VerifiedClaims(
                sub,
                clientId,
                tokenScopes,
                iss,
                aud,
                exp,
                iat,
                jti,
                kid,
                Collections.unmodifiableMap(payload),
                agentId,
                agentChain,
                notBefore);
    }

    private void verifySignature(String token, Map<String, Object> keyMap, String alg)
            throws Exception {
        SignedJWT signedJwt;
        try {
            signedJwt = SignedJWT.parse(token);
        } catch (Exception e) {
            throw new InvalidSignatureException("Failed to parse JWT: " + e.getMessage(), e);
        }

        JWSVerifier jwsVerifier = buildVerifier(keyMap, alg);
        try {
            if (!signedJwt.verify(jwsVerifier)) {
                throw new InvalidSignatureException("JWT signature verification failed");
            }
        } catch (InvalidSignatureException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidSignatureException(
                    "JWT signature verification error: " + e.getMessage(), e);
        }
    }

    private void validateClaims(Map<String, Object> payload) {
        String iss = getRequiredStringClaim(payload, "iss", false);
        if (!issuer.equals(iss)) {
            throw new InvalidClaimsException(
                    "Issuer mismatch: expected '" + issuer + "', got '" + iss + "'");
        }

        List<String> aud = extractAudience(payload);
        if (!aud.contains(resource)) {
            throw new InvalidClaimsException(
                    "Audience mismatch: required '" + resource + "' not found in aud " + aud);
        }

        getRequiredStringClaim(payload, "sub", false);
        getRequiredStringClaim(payload, "client_id", false);
        getRequiredStringClaim(payload, "jti", false);

        long now = System.currentTimeMillis() / 1000L;

        long exp = getRequiredLongClaim(payload, "exp");
        if (exp < now - clockSkewSeconds) {
            throw new TokenExpiredException(
                    "Token has expired: exp="
                            + exp
                            + ", now="
                            + now
                            + ", clockSkew="
                            + clockSkewSeconds);
        }

        Long nbf = getOptionalLongClaim(payload, "nbf"); // RFC 9068 §2.1 — nbf is optional
        if (nbf != null && nbf > now + clockSkewSeconds) {
            throw new InvalidClaimsException(
                    "Token not yet valid: nbf="
                            + nbf
                            + ", now="
                            + now
                            + ", clockSkew="
                            + clockSkewSeconds);
        }

        long iat = getRequiredLongClaim(payload, "iat");
        if (iat > now + clockSkewSeconds) {
            throw new InvalidClaimsException(
                    "Token 'iat' is in the future: iat="
                            + iat
                            + ", now="
                            + now
                            + ", clockSkew="
                            + clockSkewSeconds
                            + ". Token may have been issued with an incorrect clock.");
        }
    }

    // -----------------------------------------------------------------------
    // JWT decoding helpers
    // -----------------------------------------------------------------------

    private static Map<String, Object> decodeJsonSegment(String segment, String name) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(addPadding(segment));
            String json = new String(decoded, StandardCharsets.UTF_8);
            return JSONObjectUtils.parse(json);
        } catch (Exception e) {
            throw new InvalidSignatureException(
                    "Failed to decode JWT " + name + ": " + e.getMessage(), e);
        }
    }

    /** Base64URL segments may omit padding; add it back before decoding. */
    private static String addPadding(String s) {
        int pad = (4 - s.length() % 4) % 4;
        return s + "=".repeat(pad);
    }

    // -----------------------------------------------------------------------
    // Claim extraction helpers
    // -----------------------------------------------------------------------

    private static String getRequiredStringClaim(
            Map<String, Object> claims, String name, boolean fromHeader) {
        Object val = claims.get(name);
        if (!(val instanceof String str) || str.isBlank()) {
            String location = fromHeader ? "JWT header" : "JWT payload";
            throw new InvalidClaimsException(
                    "Required claim '" + name + "' is missing or empty in " + location);
        }
        return str;
    }

    /** Returns the claim as a Long if present, or null if the key is absent. */
    private static Long getOptionalLongClaim(Map<String, Object> claims, String name) {
        Object val = claims.get(name);
        if (val == null) return null;
        if (val instanceof Number n) return n.longValue();
        try {
            return Long.parseLong(val.toString());
        } catch (NumberFormatException e) {
            throw new InvalidClaimsException("Claim '" + name + "' is not a valid number: " + val);
        }
    }

    private static long getRequiredLongClaim(Map<String, Object> claims, String name) {
        Object val = claims.get(name);
        if (val == null) {
            throw new InvalidClaimsException("Required claim '" + name + "' is missing");
        }
        if (val instanceof Number n) return n.longValue();
        try {
            return Long.parseLong(val.toString());
        } catch (NumberFormatException e) {
            throw new InvalidClaimsException("Claim '" + name + "' is not a valid number: " + val);
        }
    }

    private static List<String> extractAudience(Map<String, Object> payload) {
        Object audObj = payload.get("aud");
        if (audObj == null) {
            throw new InvalidClaimsException("Required claim 'aud' is missing");
        }
        // Single string — most common case
        if (audObj instanceof String s) {
            return List.of(s);
        }
        // Array — accept any size; the caller checks that the configured resource is present.
        // The AS may issue tokens with multiple audiences; we only require ours is included.
        if (audObj instanceof List<?> list) {
            List<String> audiences =
                    list.stream().filter(e -> e instanceof String).map(e -> (String) e).toList();
            if (audiences.isEmpty()) {
                throw new InvalidClaimsException(
                        "Token 'aud' array is empty or contains no strings: " + list);
            }
            return audiences;
        }
        throw new InvalidClaimsException("Unrecognised 'aud' claim type: " + audObj.getClass());
    }

    /** Returns the claim as a String if present and non-blank, or empty string if absent/blank. */
    private static String getOptionalStringClaim(Map<String, Object> claims, String name) {
        Object val = claims.get(name);
        if (val instanceof String str && !str.isBlank()) {
            return str;
        }
        return "";
    }

    /** Extracts the {@code agent_chain} claim as a list of strings, or empty list if absent. */
    private static List<String> extractAgentChain(Map<String, Object> payload) {
        Object val = payload.get("agent_chain");
        if (val == null) {
            return List.of();
        }
        if (val instanceof List<?> list) {
            List<String> result = new ArrayList<>(list.size());
            for (Object element : list) {
                if (!(element instanceof String)) {
                    throw new InvalidClaimsException(
                            "Token 'agent_chain' array contains a non-String element: "
                                    + (element == null ? "null" : element.getClass().getName()));
                }
                result.add((String) element);
            }
            return Collections.unmodifiableList(result);
        }
        throw new InvalidClaimsException(
                "Unrecognised 'agent_chain' claim type: " + val.getClass());
    }

    private static List<String> parseScopes(Map<String, Object> payload) {
        Object scopeObj = payload.get("scope");
        if (!(scopeObj instanceof String scopeStr) || scopeStr.isBlank()) {
            return List.of();
        }
        return Arrays.stream(scopeStr.split(" ")).filter(s -> !s.isBlank()).toList();
    }

    // -----------------------------------------------------------------------
    // Signature verification helper
    // -----------------------------------------------------------------------

    private static JWSVerifier buildVerifier(Map<String, Object> keyMap, String alg)
            throws Exception {
        JWK jwk = JWK.parse(keyMap);
        // Per-key algorithm binding: a key designated for RS256 must not verify an RS384 token,
        // even if RS384 is in the allowed-algorithms list.
        Object keyAlg = keyMap.get("alg");
        if (keyAlg instanceof String keyAlgStr && !keyAlgStr.equals(alg)) {
            throw new InvalidSignatureException(
                    "Token algorithm '"
                            + alg
                            + "' does not match key's designated algorithm '"
                            + keyAlgStr
                            + "'");
        }
        if (jwk instanceof RSAKey rsaKey) {
            return new RSASSAVerifier(rsaKey.toRSAPublicKey());
        }
        if (jwk instanceof ECKey ecKey) {
            return new ECDSAVerifier(ecKey.toECPublicKey());
        }
        throw new InvalidSignatureException(
                "Unsupported key type: " + jwk.getKeyType() + " for alg " + alg);
    }
}
