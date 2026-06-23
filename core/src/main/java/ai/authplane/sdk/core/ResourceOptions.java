package ai.authplane.sdk.core;

import java.util.List;
import java.util.Objects;

import ai.authplane.sdk.core.dpop.InboundDPoPOptions;
import ai.authplane.sdk.core.dpop.VerificationRequestContext;
import ai.authplane.sdk.core.errors.TokenRevokedException;

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

    private ResourceOptions(Builder builder) {
        this.allowedAlgorithms = List.copyOf(builder.allowedAlgorithms);
        this.clockSkewSeconds = builder.clockSkewSeconds;
        this.revocationChecker = builder.revocationChecker;
        this.useBuiltinRevocationChecker = builder.useBuiltinRevocationChecker;
        this.failClosed = builder.failClosed;
        this.inboundDPoP = builder.inboundDPoP;
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

    /** Builder for constructing {@link ResourceOptions} instances. */
    public static final class Builder {

        private List<String> allowedAlgorithms = List.of("RS256", "ES256");
        private int clockSkewSeconds = 30;
        private RevocationChecker revocationChecker = null;
        private boolean useBuiltinRevocationChecker = false;
        private boolean failClosed = false;
        private InboundDPoPOptions inboundDPoP = null;

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
