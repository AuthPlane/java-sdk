package ai.authplane.sdk.core.fetching;

import java.time.Clock;
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
        this(fetcher, jwksUrl, refreshSeconds, onChangeCallback, Clock.systemUTC());
    }

    /**
     * Same as the four-argument constructor, but with the time source used for TTL evaluation
     * supplied by the caller.
     *
     * <p>Supported public API, not a test seam: this class has no {@code internal} package and no
     * binary-compatibility gate, so anything public here is contract. It is the only way an
     * embedder can drive refresh intervals deterministically — from a simulation clock, or from a
     * test that states elapsed time instead of waiting for it. The superclass keeps the equivalent
     * constructor package-private because {@code DocumentCache} is never constructed directly by a
     * caller outside this package.
     *
     * <p><strong>The clock must not diverge from wall time by more than a cache TTL.</strong> A
     * server {@code max-age} is turned into an absolute expiry against the system clock, in {@link
     * CacheHeaderParser}, before it ever reaches this cache — and this cache compares it against a
     * timestamp taken from the clock supplied here. Offset the two far apart and every real server
     * expiry reads as already past, so server cache directives are discarded wholesale and the
     * configured interval governs alone. That is a safe fallback rather than a failure, but it is
     * silent. Advancing the clock forward from the real present, which is what a deterministic TTL
     * test does, is fine: the offset only has to stay inside a TTL of wall time at the moment a
     * document is fetched. Threading the clock into the header parser would remove the constraint
     * and is tracked in #34.
     *
     * @param clock time source; pass {@link Clock#systemUTC()} unless driving TTL expiry
     *     deterministically
     */
    public JwksCache(
            DocumentFetcher fetcher,
            String jwksUrl,
            int refreshSeconds,
            BiConsumer<Map<String, Object>, Map<String, Object>> onChangeCallback,
            Clock clock) {
        super(fetcher, jwksUrl, refreshSeconds, "JWKS", onChangeCallback, clock);
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
