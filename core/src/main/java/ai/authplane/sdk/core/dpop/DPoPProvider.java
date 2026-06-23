package ai.authplane.sdk.core.dpop;

import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Outbound DPoP proof generator with per-origin nonce handling.
 *
 * <p>Use one provider per proof key. The provider is safe to reuse across authorization-server
 * token operations and caller-managed downstream requests.
 */
public final class DPoPProvider {

    private final DPoPKeyMaterial keyMaterial;
    private final int proofTtlSeconds;
    private final DPoPNonceStore nonceStore;

    /** Creates a provider with a 300 second proof TTL and in-memory nonce storage. */
    public DPoPProvider(DPoPKeyMaterial keyMaterial) {
        this(keyMaterial, 300, new InMemoryDPoPNonceStore());
    }

    /** Creates a provider with explicit proof TTL and nonce storage. */
    public DPoPProvider(
            DPoPKeyMaterial keyMaterial, int proofTtlSeconds, DPoPNonceStore nonceStore) {
        this.keyMaterial = Objects.requireNonNull(keyMaterial, "keyMaterial must not be null");
        if (proofTtlSeconds <= 0) {
            throw new IllegalArgumentException(
                    "DPoP proofTtlSeconds must be positive, got " + proofTtlSeconds);
        }
        this.proofTtlSeconds = proofTtlSeconds;
        this.nonceStore = Objects.requireNonNull(nonceStore, "nonceStore must not be null");
    }

    /** Returns the proof key material used by this provider. */
    public DPoPKeyMaterial keyMaterial() {
        return keyMaterial;
    }

    /** Returns the proof lifetime in seconds. */
    public int proofTtlSeconds() {
        return proofTtlSeconds;
    }

    /** Stores a nonce learned from a DPoP-protected endpoint response for later reuse. */
    public void noteNonce(String absoluteUrl, String nonce) {
        if (nonce == null || nonce.isBlank()) {
            return;
        }
        nonceStore.put(DPoPSupport.originKey(absoluteUrl), nonce);
    }

    /** Returns the current nonce associated with the origin of the supplied URL, if any. */
    public String currentNonce(String absoluteUrl) {
        return nonceStore.get(DPoPSupport.originKey(absoluteUrl));
    }

    /** Builds a signed DPoP proof without {@code ath}. */
    public String buildProof(String method, String absoluteUrl) {
        return buildProof(method, absoluteUrl, DPoPProofOptions.defaults());
    }

    /** Builds a signed DPoP proof using the supplied per-proof options. */
    public String buildProof(String method, String absoluteUrl, DPoPProofOptions options) {
        Objects.requireNonNull(options, "options must not be null");

        long iat = Instant.now().getEpochSecond();
        JWTClaimsSet.Builder claims =
                new JWTClaimsSet.Builder()
                        .claim("jti", UUID.randomUUID().toString())
                        .claim("htm", method.toUpperCase())
                        .claim("htu", DPoPSupport.normalizeHtu(absoluteUrl))
                        .issueTime(Date.from(Instant.ofEpochSecond(iat)))
                        .expirationTime(Date.from(Instant.ofEpochSecond(iat + proofTtlSeconds)));

        if (!options.nonce().isBlank()) {
            claims.claim("nonce", options.nonce());
        }
        if (!options.accessToken().isBlank()) {
            claims.claim("ath", DPoPSupport.computeAth(options.accessToken()));
        }

        SignedJWT jwt =
                new SignedJWT(
                        new JWSHeader.Builder(keyMaterial.algorithm().jwsAlgorithm())
                                .type(new JOSEObjectType("dpop+jwt"))
                                .jwk(keyMaterial.publicJwk())
                                .build(),
                        claims.build());

        try {
            jwt.sign(buildSigner());
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign DPoP proof", e);
        }
    }

    /** Builds a downstream header map containing a {@code DPoP} proof header. */
    public Map<String, String> buildHeaders(String method, String absoluteUrl) {
        return Map.of(
                "DPoP",
                buildProof(
                        method, absoluteUrl, new DPoPProofOptions(currentNonce(absoluteUrl), "")));
    }

    /** Builds a downstream header map containing a {@code DPoP} proof bound to an access token. */
    public Map<String, String> buildHeaders(String method, String absoluteUrl, String accessToken) {
        return Map.of(
                "DPoP",
                buildProof(
                        method,
                        absoluteUrl,
                        new DPoPProofOptions(currentNonce(absoluteUrl), accessToken)));
    }

    private JWSSigner buildSigner() throws JOSEException {
        return switch (keyMaterial.algorithm()) {
            case ES256 -> new ECDSASigner(keyMaterial.privateJwk().toECKey());
            case RS256 -> new RSASSASigner(keyMaterial.privateJwk().toRSAKey());
        };
    }
}
