package ai.authplane.sdk.core.dpop;

import java.text.ParseException;
import java.util.Map;
import java.util.Objects;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * Caller-owned asymmetric key material used for outbound DPoP proof generation.
 *
 * <p>The SDK retains the supplied private key for signing and derives the public JWK and RFC 7638
 * thumbprint used for DPoP binding.
 */
public final class DPoPKeyMaterial {

    private final JWK privateJwk;
    private final JWK publicJwk;
    private final DPoPAlgorithm algorithm;
    private final String thumbprint;

    private DPoPKeyMaterial(
            JWK privateJwk, JWK publicJwk, DPoPAlgorithm algorithm, String thumbprint) {
        this.privateJwk = privateJwk;
        this.publicJwk = publicJwk;
        this.algorithm = algorithm;
        this.thumbprint = thumbprint;
    }

    /** Builds DPoP key material from a private JWK. */
    public static DPoPKeyMaterial fromJwk(JWK privateJwk, DPoPAlgorithm algorithm) {
        Objects.requireNonNull(privateJwk, "privateJwk must not be null");
        Objects.requireNonNull(algorithm, "algorithm must not be null");

        if (!privateJwk.isPrivate()) {
            throw new IllegalArgumentException("DPoP key material requires a private JWK");
        }

        JWK publicJwk = privateJwk.toPublicJWK();
        validateKeyCompatibility(privateJwk, algorithm);
        try {
            return new DPoPKeyMaterial(
                    privateJwk, publicJwk, algorithm, publicJwk.computeThumbprint().toString());
        } catch (JOSEException e) {
            throw new IllegalArgumentException("Failed to compute DPoP JWK thumbprint", e);
        }
    }

    /** Builds DPoP key material from a PEM-encoded private key. */
    public static DPoPKeyMaterial fromPem(String pem, DPoPAlgorithm algorithm) {
        try {
            return fromJwk(JWK.parseFromPEMEncodedObjects(pem), algorithm);
        } catch (JOSEException e) {
            throw new IllegalArgumentException("Failed to parse DPoP PEM key", e);
        }
    }

    /** Builds DPoP key material from explicit private and public JWK maps. */
    public static DPoPKeyMaterial fromPublicAndPrivateJwks(
            Map<String, Object> privateJwk,
            Map<String, Object> publicJwk,
            DPoPAlgorithm algorithm) {
        try {
            JWK parsedPrivate = JWK.parse(privateJwk);
            JWK parsedPublic = JWK.parse(publicJwk);
            validateKeyCompatibility(parsedPrivate, algorithm);
            return new DPoPKeyMaterial(
                    parsedPrivate,
                    parsedPublic.toPublicJWK(),
                    algorithm,
                    parsedPublic.toPublicJWK().computeThumbprint().toString());
        } catch (ParseException | JOSEException e) {
            throw new IllegalArgumentException("Failed to parse DPoP JWK material", e);
        }
    }

    private static void validateKeyCompatibility(JWK privateJwk, DPoPAlgorithm algorithm) {
        switch (algorithm) {
            case RS256 -> {
                if (!(privateJwk instanceof RSAKey)) {
                    throw new IllegalArgumentException("RS256 DPoP keys must be RSA");
                }
            }
            case ES256 -> {
                if (!(privateJwk instanceof ECKey ecKey) || !Curve.P_256.equals(ecKey.getCurve())) {
                    throw new IllegalArgumentException("ES256 DPoP keys must be P-256 EC keys");
                }
            }
            default ->
                    throw new IllegalArgumentException("Unsupported DPoP algorithm: " + algorithm);
        }
    }

    JWK privateJwk() {
        return privateJwk;
    }

    /** Public JWK embedded into generated DPoP proofs. */
    public JWK publicJwk() {
        return publicJwk;
    }

    /** Configured signing algorithm for this key pair. */
    public DPoPAlgorithm algorithm() {
        return algorithm;
    }

    /** RFC 7638 thumbprint of the public proof key. */
    public String thumbprint() {
        return thumbprint;
    }
}
