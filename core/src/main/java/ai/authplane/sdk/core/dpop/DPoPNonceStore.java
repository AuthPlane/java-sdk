package ai.authplane.sdk.core.dpop;

/** Concurrency-safe storage for outbound DPoP nonces keyed by origin. */
public interface DPoPNonceStore {

    /**
     * Returns the current nonce for the given origin.
     *
     * @param origin the origin key (scheme + host + port)
     * @return the stored nonce, or an empty string if none is stored; never {@code null}
     */
    String get(String origin);

    /**
     * Stores or replaces the nonce for the given origin. Implementations should silently ignore
     * null or blank nonces.
     *
     * @param origin the origin key (scheme + host + port); must not be blank
     * @param nonce the nonce value from the {@code DPoP-Nonce} response header
     */
    void put(String origin, String nonce);
}
