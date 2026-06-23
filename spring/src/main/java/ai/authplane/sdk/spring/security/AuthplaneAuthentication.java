package ai.authplane.sdk.spring.security;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

import ai.authplane.sdk.core.VerifiedClaims;
import ai.authplane.sdk.core.errors.InsufficientScopeException;

/**
 * Spring Security {@link Authentication} token backed by Authplane's {@link VerifiedClaims}.
 *
 * <p>Implemented as a standard {@link AbstractOAuth2TokenAuthenticationToken} so {@link
 * #getToken()} (the raw access token) and {@link #getTokenAttributes()} (the claims) interoperate
 * with Spring's OAuth2 resource-server tooling, while still exposing the typed {@link #getClaims()}
 * view and scope-check helpers.
 *
 * <p>Stored in the {@link SecurityContext} after successful JWT validation. Tool handlers and
 * service methods can retrieve it via {@link #current()} or via Spring's
 * {@code @AuthenticationPrincipal} support.
 *
 * <h2>Usage in a Spring MVC / Spring AI tool handler</h2>
 *
 * <pre>{@code
 * // Option A — static helper (any class, no injection needed)
 * AuthplaneAuthentication auth = AuthplaneAuthentication.current();
 * auth.requireScope("math:add");
 *
 * // Option B — Spring MVC method parameter
 * public Result myTool(@AuthenticationPrincipal AuthplaneAuthentication auth) { ... }
 *
 * // Option C — direct SDK access
 * VerifiedClaims claims = auth.getClaims();
 * claims.requireScope("math:add");  // throws InsufficientScopeException (SDK)
 * }</pre>
 *
 * <h2>Granted authorities</h2>
 *
 * Each scope is mapped to a {@code SCOPE_<scope>} authority, matching Spring Security's default
 * convention and enabling {@code @PreAuthorize("hasAuthority('SCOPE_math:add')")} and {@code
 * .access(hasScope("math:add"))} without extra configuration.
 */
public final class AuthplaneAuthentication
        extends AbstractOAuth2TokenAuthenticationToken<OAuth2AccessToken> {

    private static final long serialVersionUID = 1L;

    private static final String SCOPE_PREFIX = "SCOPE_";

    private final VerifiedClaims claims;

    private AuthplaneAuthentication(VerifiedClaims claims, OAuth2AccessToken token) {
        super(token, claims.sub(), "", toAuthorities(claims.scopes()));
        this.claims = Objects.requireNonNull(claims, "claims must not be null");
        setAuthenticated(true);
    }

    /**
     * Creates an authenticated token from verified claims and the raw access token.
     *
     * @param claims the verified JWT claims
     * @param token the raw access-token string (exposed via {@link #getToken()})
     */
    public static AuthplaneAuthentication of(VerifiedClaims claims, String token) {
        Objects.requireNonNull(claims, "claims must not be null");
        Objects.requireNonNull(token, "token must not be null");
        OAuth2AccessToken.TokenType type =
                claims.isDpopBound()
                        ? OAuth2AccessToken.TokenType.DPOP
                        : OAuth2AccessToken.TokenType.BEARER;
        OAuth2AccessToken accessToken =
                new OAuth2AccessToken(
                        type,
                        token,
                        Instant.ofEpochSecond(claims.issuedAt()),
                        Instant.ofEpochSecond(claims.expiresAt()),
                        Set.copyOf(claims.scopes()));
        return new AuthplaneAuthentication(claims, accessToken);
    }

    /**
     * Returns the {@link AuthplaneAuthentication} from the current thread's {@link
     * SecurityContextHolder}.
     *
     * @throws IllegalStateException if the current authentication is not an {@link
     *     AuthplaneAuthentication}
     */
    public static AuthplaneAuthentication current() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof AuthplaneAuthentication a) {
            return a;
        }
        throw new IllegalStateException(
                "No AuthplaneAuthentication in SecurityContext; found: "
                        + (auth == null ? "null" : auth.getClass().getName()));
    }

    // -------------------------------------------------------------------------
    // Scope checks — Spring Security-aware (throw AccessDeniedException for 403)
    // -------------------------------------------------------------------------

    /**
     * Throws {@link AccessDeniedException} (HTTP 403) if the token does not carry {@code scope}.
     *
     * <p>Prefer this over {@link VerifiedClaims#requireScope(String)} inside Spring components —
     * Spring Security's exception handling translates {@link AccessDeniedException} to a proper 403
     * response.
     */
    public void requireScope(String scope) {
        try {
            claims.requireScope(scope);
        } catch (InsufficientScopeException e) {
            throw new AccessDeniedException(e.getMessage(), e);
        }
    }

    /** Returns {@code true} if the token carries {@code scope}. */
    public boolean hasScope(String scope) {
        return claims.hasScope(scope);
    }

    /**
     * Throws {@link AccessDeniedException} if any of the given scopes is missing. All scopes must
     * be present.
     *
     * <p>When several scopes are missing the thrown exception names <em>all</em> of them (not just
     * the first), so the {@code insufficient_scope} response tells the client every scope it still
     * needs.
     */
    public void requireAllScopes(String... scopes) {
        try {
            claims.requireScopes(List.of(scopes));
        } catch (InsufficientScopeException e) {
            throw new AccessDeniedException(e.getMessage(), e);
        }
    }

    /** Returns {@code true} only if every given scope is present. */
    public boolean hasAllScopes(String... scopes) {
        for (String scope : scopes) {
            if (!claims.hasScope(scope)) return false;
        }
        return true;
    }

    // -------------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------------

    /**
     * Returns the underlying {@link VerifiedClaims} for full SDK access, including {@link
     * VerifiedClaims#requireScope(String)} (throws {@link InsufficientScopeException}), {@link
     * VerifiedClaims#hasClaim}, and the raw claims map.
     */
    public VerifiedClaims getClaims() {
        return claims;
    }

    /** The {@code sub} claim — identifies the end user or service account. */
    public String getSubject() {
        return claims.sub();
    }

    /** The {@code client_id} claim — identifies the OAuth 2.1 client. */
    public String getClientId() {
        return claims.clientId();
    }

    /** The parsed scope list. */
    public List<String> getScopes() {
        return claims.scopes();
    }

    /**
     * Returns a single raw claim value, or {@code null} if not present. For structured access
     * prefer {@link #getClaims()}.
     */
    public Object getClaim(String key) {
        return claims.raw().get(key);
    }

    /** The complete unmodifiable raw JWT claims map. */
    public Map<String, Object> getRawClaims() {
        return claims.raw();
    }

    // -------------------------------------------------------------------------
    // AbstractOAuth2TokenAuthenticationToken
    // -------------------------------------------------------------------------

    /**
     * The token claims as an attribute map (RFC 9068), exposed for Spring resource-server tooling.
     * {@link #getToken()} returns the raw access token; {@link #getClaims()} the typed view.
     *
     * <p>Returned as an unmodifiable copy: the {@code OAuth2TokenAttributesAccessor} contract does
     * not promise immutability, so a caller mutating the result fails fast rather than corrupting
     * the shared claims snapshot.
     */
    @Override
    public Map<String, Object> getTokenAttributes() {
        return Map.copyOf(claims.raw());
    }

    /** Returns the {@code sub} claim. */
    @Override
    public String getName() {
        return claims.sub();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static Collection<GrantedAuthority> toAuthorities(List<String> scopes) {
        return scopes.stream()
                .<GrantedAuthority>map(s -> new SimpleGrantedAuthority(SCOPE_PREFIX + s))
                .toList();
    }
}
