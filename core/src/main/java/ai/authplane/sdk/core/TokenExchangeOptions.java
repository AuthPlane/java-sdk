package ai.authplane.sdk.core;

import java.util.List;
import java.util.Objects;

/**
 * Options for RFC 8693 token exchange.
 *
 * @see AuthplaneClient#exchange(TokenExchangeOptions)
 */
public final class TokenExchangeOptions {

    private final String subjectToken;
    private final String subjectTokenType;
    private final List<String> scope;
    private final List<String> resources;
    private final List<String> audiences;
    private final String actorToken;
    private final String actorTokenType;

    private TokenExchangeOptions(Builder builder) {
        this.subjectToken = builder.subjectToken;
        this.subjectTokenType = builder.subjectTokenType;
        this.scope = builder.scope != null ? List.copyOf(builder.scope) : null;
        this.resources = builder.resources != null ? List.copyOf(builder.resources) : null;
        this.audiences = builder.audiences != null ? List.copyOf(builder.audiences) : null;
        this.actorToken = builder.actorToken;
        this.actorTokenType = builder.actorTokenType;
    }

    public String subjectToken() {
        return subjectToken;
    }

    public String subjectTokenType() {
        return subjectTokenType;
    }

    public List<String> scope() {
        return scope;
    }

    public String resource() {
        return resources != null && !resources.isEmpty() ? resources.getFirst() : null;
    }

    public String audience() {
        return audiences != null && !audiences.isEmpty() ? audiences.getFirst() : null;
    }

    public List<String> resources() {
        return resources;
    }

    public List<String> audiences() {
        return audiences;
    }

    public String actorToken() {
        return actorToken;
    }

    public String actorTokenType() {
        return actorTokenType;
    }

    /** Creates a builder with the required subject token. */
    public static Builder builder(String subjectToken) {
        return new Builder(subjectToken);
    }

    /** Builder for constructing {@link TokenExchangeOptions} instances. */
    public static final class Builder {

        private final String subjectToken;
        private String subjectTokenType = "urn:ietf:params:oauth:token-type:access_token";
        private List<String> scope = null;
        private List<String> resources = null;
        private List<String> audiences = null;
        private String actorToken = null;
        private String actorTokenType = null;

        public Builder(String subjectToken) {
            Objects.requireNonNull(subjectToken, "subjectToken must not be null");
            this.subjectToken = subjectToken;
        }

        /** Overrides the default subject_token_type (access_token URN). */
        public Builder subjectTokenType(String type) {
            this.subjectTokenType = type;
            return this;
        }

        /** Scopes to request on the exchanged token. */
        public Builder scope(List<String> scope) {
            this.scope = scope;
            return this;
        }

        /** Resource indicator (RFC 8707). */
        public Builder resource(String resource) {
            this.resources = resource == null ? null : List.of(resource);
            return this;
        }

        /** Repeated resource indicators (RFC 8693 / RFC 8707). */
        public Builder resources(List<String> resources) {
            this.resources = resources;
            return this;
        }

        /** Audience for the exchanged token. */
        public Builder audience(String audience) {
            this.audiences = audience == null ? null : List.of(audience);
            return this;
        }

        /** Repeated audiences for the exchanged token. */
        public Builder audiences(List<String> audiences) {
            this.audiences = audiences;
            return this;
        }

        /** Actor token for delegation (RFC 8693 §2.1). */
        public Builder actorToken(String actorToken) {
            this.actorToken = actorToken;
            return this;
        }

        /** Actor token type URN. */
        public Builder actorTokenType(String actorTokenType) {
            this.actorTokenType = actorTokenType;
            return this;
        }

        public TokenExchangeOptions build() {
            return new TokenExchangeOptions(this);
        }
    }
}
