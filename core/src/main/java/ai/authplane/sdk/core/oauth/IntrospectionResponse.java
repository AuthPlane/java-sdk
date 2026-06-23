package ai.authplane.sdk.core.oauth;

import java.util.Map;

/**
 * Response from RFC 7662 token introspection.
 *
 * @param active whether the token is active
 * @param raw the full introspection response as an immutable map. Modifications are unsupported and
 *     callers must not attempt to mutate the returned structure.
 */
public record IntrospectionResponse(boolean active, Map<String, Object> raw) {

    public IntrospectionResponse {
        raw = raw != null ? Map.copyOf(raw) : Map.of();
    }

    /**
     * Returns the {@code cnf} confirmation claim as an immutable map, or an empty map when absent.
     *
     * <p>For a DPoP-bound access token, RFC 9449 §6.2 places {@code cnf} (with a {@code jkt}
     * member) as a top-level member of the introspection response. Bearer tokens carry no {@code
     * cnf}.
     *
     * @return the top-level {@code cnf} object, or an empty map
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> cnf() {
        if (raw.get("cnf") instanceof Map<?, ?> map) {
            return Map.copyOf((Map<String, Object>) map);
        }
        return Map.of();
    }

    /**
     * Returns the DPoP JWK thumbprint from the top-level {@code cnf.jkt} (RFC 9449 §6.2), or {@code
     * null} when the token is not DPoP-bound.
     *
     * @return the {@code jkt} thumbprint, or {@code null} if absent
     */
    public String dpopThumbprint() {
        Object jkt = cnf().get("jkt");
        return jkt instanceof String s && !s.isBlank() ? s : null;
    }
}
