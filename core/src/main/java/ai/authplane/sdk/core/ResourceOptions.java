package ai.authplane.sdk.core;

import java.net.URI;
import java.util.List;
import java.util.Objects;

import ai.authplane.sdk.core.dpop.InboundDPoPOptions;
import ai.authplane.sdk.core.dpop.VerificationRequestContext;
import ai.authplane.sdk.core.errors.TokenRevokedException;
import ai.authplane.sdk.core.prm.ProtectedResourceMetadata;

/**
 * Per-resource configuration beyond the required resource and scopes.
 *
 * <p>Use {@link #defaults()} for standard settings, or {@link #builder()} to customise algorithms,
 * clock skew, or revocation checking.
 *
 * <p>Revocation checking has three modes:
 *
 * <ol>
 *   <li><b>Disabled</b> (default) — no revocation checking.
 *   <li><b>Built-in</b> ({@link Builder#useBuiltinRevocationChecker()}) — uses RFC 7662 token
 *       introspection via the parent {@link AuthplaneClient}'s metadata cache, credentials, and
 *       transport. Fails open on errors.
 *   <li><b>Custom</b> ({@link Builder#revocationChecker(RevocationChecker)}) — uses a user-provided
 *       checker (e.g. Redis blocklist, database lookup).
 * </ol>
 */
public final class ResourceOptions {

    private final List<String> allowedAlgorithms;
    private final int clockSkewSeconds;
    private final RevocationChecker revocationChecker;
    private final boolean useBuiltinRevocationChecker;
    private final boolean failClosed;
    private final InboundDPoPOptions inboundDPoP;
    private final String resourceMetadataUrl;

    private ResourceOptions(Builder builder) {
        this.allowedAlgorithms = List.copyOf(builder.allowedAlgorithms);
        this.clockSkewSeconds = builder.clockSkewSeconds;
        this.revocationChecker = builder.revocationChecker;
        this.useBuiltinRevocationChecker = builder.useBuiltinRevocationChecker;
        this.failClosed = builder.failClosed;
        this.inboundDPoP = builder.inboundDPoP;
        this.resourceMetadataUrl = builder.resourceMetadataUrl;
    }

    /** Default options: RS256+ES256, 30s clock skew, no revocation checking. */
    public static ResourceOptions defaults() {
        return new Builder().build();
    }

    /** Returns a builder for custom resource configuration. */
    public static Builder builder() {
        return new Builder();
    }

    /** Allowed JWT signing algorithms for access token validation. */
    public List<String> allowedAlgorithms() {
        return allowedAlgorithms;
    }

    /** Clock skew applied to token time-based claims. */
    public int clockSkewSeconds() {
        return clockSkewSeconds;
    }

    /** Custom revocation checker, if one was configured. */
    public RevocationChecker revocationChecker() {
        return revocationChecker;
    }

    /** Whether built-in RFC 7662 revocation checking is enabled. */
    public boolean useBuiltinRevocationChecker() {
        return useBuiltinRevocationChecker;
    }

    /**
     * Whether the verifier rejects tokens when the revocation check fails with an exception.
     *
     * <p>When {@code false} (default), revocation check errors are logged and the token is accepted
     * (fail-open). When {@code true}, any exception from the revocation checker causes the token to
     * be rejected with a {@link TokenRevokedException}.
     */
    public boolean failClosed() {
        return failClosed;
    }

    /**
     * Inbound DPoP validation settings, or {@code null} when DPoP is not supported by this
     * resource.
     *
     * <p>Presence is the on/off switch: passing any instance — even a default-constructed one —
     * turns on PRM advertising of {@code dpop_signing_alg_values_supported} and {@code
     * dpop_bound_access_tokens_required}, and enables verify-time DPoP enforcement. {@code null}
     * (the default) keeps DPoP out of the PRM and rejects any DPoP signal at verify time. See
     * {@link AuthplaneResource#verify(String, VerificationRequestContext)} for the three
     * enforcement modes.
     */
    public InboundDPoPOptions inboundDPoP() {
        return inboundDPoP;
    }

    /**
     * The URL the {@code resource_metadata} parameter of a {@code WWW-Authenticate} challenge
     * points at, or {@code null} (the default) to advertise the resource-hosted document the SDK
     * derives from the resource identifier. See {@link Builder#resourceMetadataUrl(String)}.
     */
    public String resourceMetadataUrl() {
        return resourceMetadataUrl;
    }

    /** Builder for constructing {@link ResourceOptions} instances. */
    public static final class Builder {

        private List<String> allowedAlgorithms = List.of("RS256", "ES256");
        private int clockSkewSeconds = 30;
        private RevocationChecker revocationChecker = null;
        private boolean useBuiltinRevocationChecker = false;
        private boolean failClosed = false;
        private InboundDPoPOptions inboundDPoP = null;
        private String resourceMetadataUrl = null;

        private Builder() {}

        public Builder allowedAlgorithms(List<String> algorithms) {
            this.allowedAlgorithms = Objects.requireNonNull(algorithms);
            return this;
        }

        public Builder clockSkewSeconds(int seconds) {
            this.clockSkewSeconds = seconds;
            return this;
        }

        /**
         * Enables inbound DPoP proof validation for {@link AuthplaneResource#verify(String,
         * VerificationRequestContext)} and turns on DPoP advertising in the resource's Protected
         * Resource Metadata. Pass {@link InboundDPoPOptions#withRequired(boolean)
         * options.withRequired(true)} to also require DPoP-bound access tokens (rejecting
         * bearer-only tokens at verify time).
         */
        public Builder inboundDPoP(InboundDPoPOptions options) {
            this.inboundDPoP = Objects.requireNonNull(options, "options must not be null");
            return this;
        }

        /**
         * Points the {@code resource_metadata} parameter of every {@code WWW-Authenticate}
         * challenge at {@code url} instead of the resource-hosted RFC 9728 document the SDK derives
         * from the resource identifier ({@code <resource
         * origin>/.well-known/oauth-protected-resource[/path]}).
         *
         * <p>Set this when the document lives somewhere else — typically the copy the authorization
         * server publishes for a registered resource — and the resource server cannot, or does not
         * want to, serve the well-known path itself. The document that URL returns must still carry
         * the exact resource identifier this resource is configured with as its {@code resource}
         * member (RFC 9728 §3.3), or clients discard it.
         *
         * <p>The URL must be absolute, with an {@code http} or {@code https} scheme and a host, no
         * fragment, no userinfo, and a query that is a valid RFC 3986 §3.4 query. Plain {@code
         * http} is accepted on any host: the derived PRM URL this value replaces is not
         * scheme-narrowed either.
         *
         * @param url absolute URL of the Protected Resource Metadata document
         * @throws IllegalArgumentException if {@code url} is not an absolute http(s) URL naming a
         *     host, or carries a fragment, userinfo, or an out-of-grammar query
         */
        public Builder resourceMetadataUrl(String url) {
            Objects.requireNonNull(url, "url must not be null");
            this.resourceMetadataUrl = requireAbsoluteHttpUrl(url);
            return this;
        }

        /**
         * Shape gate for {@link #resourceMetadataUrl(String)}: the value is spliced verbatim into a
         * header that reaches unauthenticated callers, so anything that is not an absolute {@code
         * http(s)} URL naming a host is refused where the operator wrote it rather than advertised.
         *
         * <p>{@code http} is accepted on any host, with no comparison against the resource
         * identifier's own scheme: the derived PRM URL this value replaces is not scheme-narrowed
         * either, and a narrower gate refuses the in-cluster and docker-compose topologies dev mode
         * exists to serve.
         *
         * <p>The userinfo, fragment and query gates are the identifier's own, reused verbatim: this
         * value reaches the same {@code resource_metadata} sink the identifier does, and {@code
         * URI.getHost()} is non-null for {@code https://svc:secret@host/x}, so without them a
         * credential in the authority would be advertised in every 401 and 403. The query gate is
         * the one {@code URI.create} cannot stand in for — it rejects only space, {@code "}, {@code
         * \}, {@code |}, {@code ^}, <code>{</code>, <code>}</code>, {@code <} and {@code >}, so a
         * raw non-ASCII octet would otherwise ship into the header. Their messages elide secrets,
         * which is why the failure is re-reported around them rather than through {@link
         * #rejection(String, String)} — that one embeds the raw value.
         */
        private static String requireAbsoluteHttpUrl(String url) {
            try {
                ProtectedResourceMetadata.requireNoFragment(url);
                ProtectedResourceMetadata.requireValidQuery(url);
                ProtectedResourceMetadata.requireNoUserinfo(url);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(
                        "resourceMetadataUrl is not usable as the resource_metadata parameter of a"
                                + " WWW-Authenticate challenge: "
                                + e.getMessage(),
                        e);
            }
            URI uri;
            try {
                uri = URI.create(url);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(rejection(url, "it does not parse as a URI"), e);
            }
            String scheme = uri.getScheme();
            if (scheme == null) {
                throw new IllegalArgumentException(rejection(url, "it has no scheme"));
            }
            if (!"https".equalsIgnoreCase(scheme) && !"http".equalsIgnoreCase(scheme)) {
                throw new IllegalArgumentException(
                        rejection(url, "its scheme is \"" + scheme + "\", not http or https"));
            }
            if (uri.getHost() == null || uri.getHost().isBlank()) {
                throw new IllegalArgumentException(rejection(url, "it names no host"));
            }
            return url;
        }

        private static String rejection(String url, String reason) {
            return "resourceMetadataUrl \""
                    + url
                    + "\" is not usable as the resource_metadata parameter of a WWW-Authenticate"
                    + " challenge: "
                    + reason
                    + ". Configure the absolute URL clients should fetch the RFC 9728 document"
                    + " from, e.g. https://auth.example.com/.well-known/oauth-protected-resource/mcp.";
        }

        /**
         * Configures the verifier to reject tokens when the revocation check fails with an
         * exception.
         *
         * <p>By default (fail-open), revocation check errors are logged and the token is accepted.
         * With fail-closed, any exception from the revocation checker causes the token to be
         * rejected.
         */
        public Builder failClosed() {
            this.failClosed = true;
            return this;
        }

        /**
         * Plugs in a custom revocation checker.
         *
         * <p>Mutually exclusive with {@link #useBuiltinRevocationChecker()}.
         */
        public Builder revocationChecker(RevocationChecker checker) {
            if (useBuiltinRevocationChecker) {
                throw new IllegalStateException(
                        "Built-in introspection is already enabled; cannot also set a custom RevocationChecker");
            }
            this.revocationChecker = checker;
            return this;
        }

        /**
         * Enables built-in RFC 7662 token introspection revocation checking.
         *
         * <p>When the resource is created via {@link AuthplaneClient#resource(String, List,
         * ResourceOptions)}, this creates an introspection-based {@link RevocationChecker} that
         * reads the {@code introspection_endpoint} from the client's live metadata cache, uses the
         * client's AS credentials for HTTP Basic auth, and routes through the client's SSRF-safe
         * transport.
         *
         * <p>Fails open on transport and endpoint errors: network errors, HTTP errors, and missing
         * endpoints all accept the token. A successful introspection response rejects the token
         * unless {@code active} is explicitly {@code true}.
         *
         * <p>Mutually exclusive with {@link #revocationChecker(RevocationChecker)}.
         */
        public Builder useBuiltinRevocationChecker() {
            if (revocationChecker != null) {
                throw new IllegalStateException(
                        "A custom RevocationChecker is already set; cannot also enable built-in introspection");
            }
            this.useBuiltinRevocationChecker = true;
            return this;
        }

        public ResourceOptions build() {
            return new ResourceOptions(this);
        }
    }
}
