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
     * /.well-known/oauth-protected-resource} after the authority:
     *
     * <pre>
     * "https://api.example.com"        → "/.well-known/oauth-protected-resource"
     * "https://api.example.com/mcp"    → "/.well-known/oauth-protected-resource/mcp"
     * "https://api.example.com/mcp/"   → "/.well-known/oauth-protected-resource/mcp"
     * "https://api.example.com/mcp//"  → "/.well-known/oauth-protected-resource/mcp"
     * "https://api.example.com/v2/mcp" → "/.well-known/oauth-protected-resource/v2/mcp"
     * "https://api.example.com/a%2Fb"  → "/.well-known/oauth-protected-resource/a%2Fb"
     * </pre>
     *
     * <p>Per RFC 9728 §3.1 every terminating slash of the resource path is stripped when deriving
     * the well-known path; it does not affect the resource identifier itself. The derivation reads
     * the raw (percent-encoded) path, so an encoded octet such as {@code %2F} is carried through
     * verbatim rather than decoded into a path separator — decoding it would name a different path
     * than the resource identifier does.
     *
     * @param resourceUri the resource server URI; must be hierarchical and carry a scheme and an
     *     authority
     * @return the URL path (including leading slash) where the PRM should be served
     * @throws IllegalArgumentException if {@code resourceUri} is opaque, has no scheme, or has no
     *     authority
     */
    public static String wellKnownPath(URI resourceUri) {
        requireDerivable(resourceUri);

        // Read the raw path: URI.getPath() percent-decodes, which would turn a resource
        // identifier of ".../a%2Fb" into the well-known path ".../a/b" — a different path than
        // the identifier names, and the silent rewrite this derivation exists to avoid.
        String path = resourceUri.getRawPath();
        if (path == null || path.isEmpty()) {
            return WELL_KNOWN_PREFIX;
        }

        // Strip every terminating slash before deriving the well-known path (RFC 9728 §3.1):
        // the resource identity is preserved elsewhere, but the derived .well-known path must
        // not carry a trailing slash ("/mcp/" and "/mcp//" both → ".../mcp"). Stripping only one
        // would make this helper and wellKnownUrl disagree on a doubled slash.
        String derivedPath = path.replaceAll("/+$", "");
        if (derivedPath.isEmpty()) {
            return WELL_KNOWN_PREFIX;
        }

        // Strip leading slash — WELL_KNOWN_PREFIX already starts with /
        String cleanPath = derivedPath.startsWith("/") ? derivedPath.substring(1) : derivedPath;
        return WELL_KNOWN_PREFIX + "/" + cleanPath;
    }

    /**
     * Computes the full URL of the PRM document for the given resource URI.
     *
     * <p>The path component is derived by {@link #wellKnownPath(URI)}, so both helpers agree by
     * construction: the slash stripping happens in exactly one place.
     *
     * @param resourceUri the resource server URI string; must be hierarchical and carry a scheme
     *     and an authority
     * @return the full PRM document URL
     * @throws IllegalArgumentException if {@code resourceUri} is opaque, has no scheme, or has no
     *     authority
     */
    public static String wellKnownUrl(String resourceUri) {
        URI uri = URI.create(resourceUri);
        requireDerivable(uri);
        // getRawAuthority(): the raw-preservation rule applies to every component, the authority
        // included. getAuthority() percent-decodes, so "u%40b@host" derived "u@b@host" — an
        // authority structurally different from the one the identifier names.
        return uri.getScheme() + "://" + uri.getRawAuthority() + wellKnownPath(uri);
    }

    /**
     * Guards the PRM derivation helpers against identifiers they cannot derive from.
     *
     * <p>RFC 8707 §2 permits a resource indicator that is any absolute URI, and this class stores
     * whatever it is given verbatim — {@code urn:example:api} is a valid resource identifier. But
     * an opaque URI has no authority and no hierarchical path, so there is no PRM URL to publish
     * for it: the derivation would otherwise emit {@code urn://null/.well-known/...} and hand that
     * to the {@code resource_metadata} parameter of the 401 challenge.
     *
     * <p>The scheme is gated for the same reason, and needs its own test: a scheme-relative
     * reference such as {@code //api.example.com/mcp} is neither opaque nor authority-less, so it
     * clears both of the checks above. The derivation then reads a null scheme and emits {@code
     * null://api.example.com/.well-known/oauth-protected-resource/mcp} into that same challenge
     * parameter. RFC 8707 §2 requires the resource indicator to be an absolute URI, and RFC 3986
     * §4.3 defines one as always carrying a scheme, so no legitimate identifier is turned away.
     */
    private static void requireDerivable(URI resourceUri) {
        if (resourceUri.isOpaque()
                || resourceUri.getScheme() == null
                || resourceUri.getAuthority() == null) {
            throw new IllegalArgumentException(
                    "Cannot derive a Protected Resource Metadata URL from \""
                            + resourceUri
                            + "\": PRM derivation requires a hierarchical resource identifier with"
                            + " a scheme and an authority (e.g. https://api.example.com/mcp). The"
                            + " resource identifier itself may be any absolute URI permitted by RFC"
                            + " 8707 §2 and is stored verbatim; only the derivation is"
                            + " restricted.");
        }
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
