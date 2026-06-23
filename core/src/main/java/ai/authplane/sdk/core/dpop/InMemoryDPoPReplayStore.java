package ai.authplane.sdk.core.dpop;

import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/** In-memory replay store suitable for development and single-process deployments. */
public final class InMemoryDPoPReplayStore implements DPoPReplayStore {

    private static final int DEFAULT_MAX_ENTRIES = 10_000;

    private final int maxEntries;
    private final Map<String, Instant> expiries = new LinkedHashMap<>();

    public InMemoryDPoPReplayStore() {
        this(DEFAULT_MAX_ENTRIES);
    }

    /** Creates a replay store with the specified maximum number of entries. */
    public InMemoryDPoPReplayStore(int maxEntries) {
        if (maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries must be positive");
        }
        this.maxEntries = maxEntries;
    }

    @Override
    public synchronized boolean storeIfAbsent(String jti, Instant expiresAt) {
        if (jti == null || jti.isBlank()) {
            throw new IllegalArgumentException("jti must not be blank");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt must not be null");
        }

        Instant now = Instant.now();
        evictExpired(now);

        Instant existing = expiries.get(jti);
        if (existing != null && existing.isAfter(now)) {
            return false;
        }

        if (expiries.size() >= maxEntries) {
            throw new IllegalStateException(
                    "DPoP replay store is at capacity ("
                            + maxEntries
                            + "); "
                            + "consider using a distributed store for high-throughput deployments");
        }

        expiries.put(jti, expiresAt);
        return true;
    }

    // Insertion-ordered: proofs arrive with monotonically increasing expiry,
    // so we can stop at the first non-expired entry. Still O(n) in the
    // degenerate case where all entries are non-expired, but bounded by
    // maxEntries and typically only a few entries are evicted per call.
    private void evictExpired(Instant now) {
        Iterator<Map.Entry<String, Instant>> iterator = expiries.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, Instant> entry = iterator.next();
            if (entry.getValue().isAfter(now)) {
                break;
            }
            iterator.remove();
        }
    }
}
