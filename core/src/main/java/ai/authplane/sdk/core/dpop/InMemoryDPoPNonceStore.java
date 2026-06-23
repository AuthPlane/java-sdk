package ai.authplane.sdk.core.dpop;

import java.util.LinkedHashMap;

/** Bounded in-memory nonce store suitable for single-process deployments. */
public final class InMemoryDPoPNonceStore implements DPoPNonceStore {

    private final int maxEntries;
    private final LinkedHashMap<String, String> entries = new LinkedHashMap<>(16, 0.75f, true);

    public InMemoryDPoPNonceStore() {
        this(256);
    }

    /** Creates a nonce store with the specified maximum number of entries. */
    public InMemoryDPoPNonceStore(int maxEntries) {
        if (maxEntries <= 0) {
            throw new IllegalArgumentException(
                    "DPoP nonce store maxEntries must be positive, got " + maxEntries);
        }
        this.maxEntries = maxEntries;
    }

    @Override
    public synchronized String get(String origin) {
        String nonce = entries.get(origin);
        return nonce != null ? nonce : "";
    }

    @Override
    public synchronized void put(String origin, String nonce) {
        if (origin == null || origin.isBlank()) {
            throw new IllegalArgumentException("origin must not be blank");
        }
        if (nonce == null || nonce.isBlank()) {
            return;
        }

        entries.put(origin, nonce);
        while (entries.size() > maxEntries) {
            entries.remove(entries.keySet().iterator().next());
        }
    }
}
