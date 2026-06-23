package ai.authplane.sdk.core.errors;

import java.io.Serial;
import java.util.List;

/**
 * Thrown when a required OAuth scope is not present in the verified token. Maps to HTTP 403
 * Forbidden (not 401 — the token is valid but lacks permission).
 */
public class InsufficientScopeException extends AuthplaneException {

    @Serial private static final long serialVersionUID = 1L;

    private final String requiredScope;
    private transient List<String> requiredScopes;
    private transient List<String> availableScopes;

    /** Creates an exception indicating the token lacks the single required scope. */
    public InsufficientScopeException(String requiredScope, List<String> availableScopes) {
        this(List.of(requiredScope), availableScopes);
    }

    /**
     * Creates an exception indicating the token is missing one or more of {@code requiredScopes}
     * (logical AND). The message names every <em>missing</em> scope so the RFC 6750 {@code
     * error_description} (derived from {@link #getMessage()}) doesn't surface just the first one,
     * while {@link #getRequiredScopes()} carries the full requested set.
     *
     * @param requiredScopes all scopes the caller required; must be non-empty
     * @param availableScopes the scopes actually present on the token
     */
    public InsufficientScopeException(List<String> requiredScopes, List<String> availableScopes) {
        super(buildMessage(requiredScopes, availableScopes));
        this.requiredScopes = List.copyOf(requiredScopes);
        this.requiredScope = this.requiredScopes.get(0);
        this.availableScopes = List.copyOf(availableScopes);
    }

    private static String buildMessage(List<String> requiredScopes, List<String> availableScopes) {
        // An empty token renders as "(none)" rather than "[]" — clearer in the error_description.
        String available = availableScopes.isEmpty() ? "(none)" : availableScopes.toString();
        if (requiredScopes.size() == 1) {
            return String.format(
                    "Insufficient scope: required '%s', token has %s",
                    requiredScopes.get(0), available);
        }
        List<String> missing =
                requiredScopes.stream().filter(s -> !availableScopes.contains(s)).toList();
        return String.format(
                "Insufficient scope: required %s, missing %s, token has %s",
                requiredScopes, missing, available);
    }

    /**
     * The first required scope. Retained for backwards compatibility with single-scope callers; use
     * {@link #getRequiredScopes()} to see the full set requested by a multi-scope check.
     */
    public String getRequiredScope() {
        return requiredScope;
    }

    /** All scopes the caller required (the full requested set), in request order. */
    public List<String> getRequiredScopes() {
        return requiredScopes;
    }

    public List<String> getAvailableScopes() {
        return availableScopes;
    }
}
