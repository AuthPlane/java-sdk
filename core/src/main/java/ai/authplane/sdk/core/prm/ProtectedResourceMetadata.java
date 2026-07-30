package ai.authplane.sdk.core.prm;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.nimbusds.jose.util.JSONObjectUtils;

/**
 * Builds and represents a RFC 9728 Protected Resource Metadata document.
 *
 * <p>Serve the document at the well-known URL computed by {@link #wellKnownPath(URI)}.
 *
 * <p>Example:
 *
 * <pre>{@code
 * ProtectedResourceMetadata prm = ProtectedResourceMetadata.builder()
 *     .resource("https://api.example.com")
 *     .authorizationServer("https://auth.example.com")
 *     .scopes(List.of("read:data", "write:data"))
 *     .build();
 *
 * // Serve prm.toMap() as JSON at prm.wellKnownPath()
 * String path = ProtectedResourceMetadata.wellKnownPath(URI.create("https://api.example.com"));
 * // path = "/.well-known/oauth-protected-resource"
 * }</pre>
 */
public final class ProtectedResourceMetadata {

    private static final String WELL_KNOWN_PREFIX = "/.well-known/oauth-protected-resource";

    private final String resource;
    private final List<String> authorizationServers;
    private final List<String> bearerMethodsSupported;
    private final List<String> scopesSupported;

    private ProtectedResourceMetadata(
            String resource,
            List<String> authorizationServers,
            List<String> bearerMethodsSupported,
            List<String> scopesSupported) {
        this.resource = resource;
        this.authorizationServers = List.copyOf(authorizationServers);
        this.bearerMethodsSupported = List.copyOf(bearerMethodsSupported);
        this.scopesSupported = List.copyOf(scopesSupported);
    }

    // -----------------------------------------------------------------------
    // Well-known path derivation
    // -----------------------------------------------------------------------

    /**
     * Computes the URL path at which this resource server should serve its PRM document.
     *
     * <p>The path is derived from the resource URI by inserting {@code
     * /.well-known/oauth-protected-resource} after the authority. Trailing slashes on the resource
     * path are dropped, so identifiers differing only by a trailing slash resolve to the same
     * metadata document (RFC 9728 §3):
     *
     * <pre>
     * "https://api.example.com"        → "/.well-known/oauth-protected-resource"
     * "https://api.example.com/"       → "/.well-known/oauth-protected-resource"
     * "https://api.example.com/mcp"    → "/.well-known/oauth-protected-resource/mcp"
     * "https://api.example.com/mcp/"   → "/.well-known/oauth-protected-resource/mcp"
     * "https://api.example.com/v2/mcp" → "/.well-known/oauth-protected-resource/v2/mcp"
     * </pre>
     *
     * @param resourceUri the resource server URI
     * @return the URL path (including leading slash) where the PRM should be served
     */
    public static String wellKnownPath(URI resourceUri) {
        String path = resourceUri.getPath();
        if (path == null || path.isEmpty()) {
            return WELL_KNOWN_PREFIX;
        }

        // Drop trailing slashes — "/mcp/" and "/mcp" must map to the same document
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        if (path.isEmpty()) {
            return WELL_KNOWN_PREFIX;
        }

        // Strip leading slash — WELL_KNOWN_PREFIX already starts with /
        String cleanPath = path.startsWith("/") ? path.substring(1) : path;
        return WELL_KNOWN_PREFIX + "/" + cleanPath;
    }

    /**
     * Computes the full URL of the PRM document for the given resource URI.
     *
     * <p>Applies the same trailing-slash normalization as {@link #wellKnownPath(URI)}.
     *
     * @param resourceUri the resource server URI string
     * @return the full PRM document URL
     */
    public static String wellKnownUrl(String resourceUri) {
        URI uri = URI.create(resourceUri);
        return uri.getScheme() + "://" + uri.getAuthority() + wellKnownPath(uri);
    }

    // -----------------------------------------------------------------------
    // Document serialization
    // -----------------------------------------------------------------------

    /**
     * Returns the PRM document as a JSON string, correctly handling strings, arrays, booleans, and
     * special characters.
     */
    public String toJson() {
        return JSONObjectUtils.toJSONString(toMap());
    }

    /**
     * Returns the PRM document as an unmodifiable Map suitable for JSON serialization.
     *
     * <p>Key ordering is deterministic (insertion order via LinkedHashMap).
     */
    public Map<String, Object> toMap() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("resource", resource);
        doc.put("authorization_servers", authorizationServers);
        doc.put("bearer_methods_supported", bearerMethodsSupported);
        doc.put("scopes_supported", scopesSupported);
        return Collections.unmodifiableMap(doc);
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    public String getResource() {
        return resource;
    }

    public List<String> getAuthorizationServers() {
        return authorizationServers;
    }

    public List<String> getBearerMethodsSupported() {
        return bearerMethodsSupported;
    }

    public List<String> getScopesSupported() {
        return scopesSupported;
    }

    // -----------------------------------------------------------------------
    // Builder
    // -----------------------------------------------------------------------

    public static Builder builder() {
        return new Builder();
    }

    /** Builder for constructing {@link ProtectedResourceMetadata} instances. */
    public static final class Builder {

        private String resource;
        private String authorizationServer;
        private List<String> scopes = List.of();

        private Builder() {}

        /** The resource server URI. Must match the {@code aud} claim in tokens. Required. */
        public Builder resource(String resource) {
            this.resource = resource;
            return this;
        }

        /**
         * The Authorization Server issuer URI. Required. Typically the same as the {@code iss}
         * claim in tokens.
         */
        public Builder authorizationServer(String issuer) {
            this.authorizationServer = issuer;
            return this;
        }

        /** The scopes supported by this resource server. */
        public Builder scopes(List<String> scopes) {
            this.scopes = List.copyOf(scopes);
            return this;
        }

        /** Constructs an immutable {@link ProtectedResourceMetadata} instance from this builder. */
        public ProtectedResourceMetadata build() {
            Objects.requireNonNull(resource, "resource is required");
            Objects.requireNonNull(authorizationServer, "authorizationServer is required");
            if (resource.isBlank())
                throw new IllegalArgumentException("resource must not be blank");
            if (authorizationServer.isBlank())
                throw new IllegalArgumentException("authorizationServer must not be blank");

            return new ProtectedResourceMetadata(
                    resource, List.of(authorizationServer), List.of("header"), scopes);
        }
    }
}
