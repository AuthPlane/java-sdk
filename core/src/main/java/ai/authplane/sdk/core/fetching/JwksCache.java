package ai.authplane.sdk.core.fetching;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.logging.Logger;

/**
 * Cache for a JWKS (JSON Web Key Set) document with key-by-kid lookup.
 *
 * <p>Extends DocumentCache with: - getKeyByKid(kid) — finds the JWK with matching kid, or empty -
 * getKeyByKid(kid, forceRefresh) — forces a JWKS refresh if kid not found
 */
public class JwksCache extends DocumentCache {

    private static final Logger LOG = Logger.getLogger(JwksCache.class.getName());

    public JwksCache(
            DocumentFetcher fetcher,
            String jwksUrl,
            int refreshSeconds,
            BiConsumer<Map<String, Object>, Map<String, Object>> onChangeCallback) {
        super(fetcher, jwksUrl, refreshSeconds, "JWKS", onChangeCallback);
    }

    /**
     * Returns the JWK map for the given kid, or empty if not present in the current cache.
     *
     * @param kid the key ID from the JWT header
     * @param forceRefresh if true, refresh the JWKS before looking up
     */
    @SuppressWarnings("unchecked")
    public Optional<Map<String, Object>> getKeyByKid(String kid, boolean forceRefresh)
            throws Exception {
        Map<String, Object> jwks = forceRefresh ? forceRefresh() : get();

        Object keysObj = jwks.get("keys");
        if (!(keysObj instanceof List<?> keys)) {
            LOG.warning("JWKS document has no 'keys' array");
            return Optional.empty();
        }

        for (Object keyObj : keys) {
            if (keyObj instanceof Map<?, ?> key) {
                Object keyKid = key.get("kid");
                if (kid.equals(keyKid) && isUsableForSignatureVerification(key)) {
                    return Optional.of((Map<String, Object>) key);
                }
            }
        }

        LOG.fine(
                () ->
                        "kid '"
                                + kid
                                + "' not found in JWKS"
                                + (forceRefresh ? " (after force refresh)" : ""));
        return Optional.empty();
    }

    private static boolean isUsableForSignatureVerification(Map<?, ?> key) {
        Object use = key.get("use");
        if (use instanceof String useValue && !"sig".equals(useValue)) {
            return false;
        }

        Object keyOps = key.get("key_ops");
        if (keyOps instanceof List<?> operations) {
            return operations.stream().anyMatch("verify"::equals);
        }

        return true;
    }
}
