package ai.authplane.sdk.core.fetching;

import java.util.Map;
import java.util.Objects;

/**
 * The result of a successful document fetch.
 *
 * @param document The parsed JSON document as an immutable map. Modifications are unsupported and
 *     callers must not attempt to mutate the returned structure.
 * @param expiresAt Unix epoch seconds when this document should be considered expired, or null if
 *     no cache expiry was communicated by the server. Callers apply their own TTL when null.
 */
public record FetchResult(Map<String, Object> document, Long expiresAt) {
    public FetchResult {
        Objects.requireNonNull(document, "document must not be null");
        document = Map.copyOf(document);
    }

    /** Returns true if the server provided an explicit expiry time. */
    public boolean hasServerExpiry() {
        return expiresAt != null;
    }
}
