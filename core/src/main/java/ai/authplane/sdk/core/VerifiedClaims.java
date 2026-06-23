package ai.authplane.sdk.core;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ai.authplane.sdk.core.errors.InsufficientScopeException;

/**
 * Immutable value object containing all validated claims from a verified JWT.
 *
 * <p>All fields are guaranteed non-null and non-empty. {@code scopes}, {@code audience}, and {@code
 * agentChain} are unmodifiable lists. {@code raw} is an unmodifiable snapshot of the full JWT
 * payload at verification time.
 *
 * <p>Instances are safe to pass between threads without synchronization.
 */
public record VerifiedClaims(
        /** Subject — identifies the end user or principal (JWT {@code sub} claim). */
        String sub,

        /** OAuth 2.1 client ID that requested the token ({@code client_id} claim). */
        String clientId,

        /**
         * Granted scopes, parsed from the space-separated JWT {@code scope} claim. Never null;
         * empty list if no scopes were granted.
         */
        List<String> scopes,

        /** Token issuer — matched exactly against the configured issuer ({@code iss}). */
        String issuer,

        /**
         * All audiences from the token's {@code aud} claim. The configured resource URI is
         * guaranteed to be present in this list.
         */
        List<String> audience,

        /** Unix epoch seconds at which the token expires ({@code exp}). */
        long expiresAt,

        /** Unix epoch seconds at which the token was issued ({@code iat}). */
        long issuedAt,

        /** Unique JWT identifier ({@code jti}). */
        String jti,

        /** Key ID used to sign this token ({@code kid} JWT header). */
        String kid,

        /**
         * Complete unmodifiable snapshot of the raw JWT payload (all claims). Useful for accessing
         * non-standard claims such as custom extensions. Modifications are unsupported and callers
         * must not attempt to mutate the returned structure.
         */
        Map<String, Object> raw,

        /** Agent identifier ({@code agent_id} claim). Empty string when the claim is absent. */
        String agentId,

        /**
         * Agent delegation chain ({@code agent_chain} claim). Empty list when the claim is absent.
         * The returned list is unmodifiable.
         */
        List<String> agentChain,

        /**
         * Unix epoch seconds before which the token must not be accepted ({@code nbf} claim). Zero
         * when the claim is absent.
         */
        long notBefore) {
    /**
     * Validates that all required claims are non-null and makes defensive copies of collections.
     */
    public VerifiedClaims {
        Objects.requireNonNull(sub, "sub must not be null");
        Objects.requireNonNull(clientId, "clientId must not be null");
        Objects.requireNonNull(scopes, "scopes must not be null");
        Objects.requireNonNull(issuer, "issuer must not be null");
        Objects.requireNonNull(audience, "audience must not be null");
        Objects.requireNonNull(jti, "jti must not be null");
        Objects.requireNonNull(kid, "kid must not be null");
        Objects.requireNonNull(raw, "raw must not be null");
        Objects.requireNonNull(agentId, "agentId must not be null");
        Objects.requireNonNull(agentChain, "agentChain must not be null");
        scopes = List.copyOf(scopes);
        audience = List.copyOf(audience);
        raw = Map.copyOf(raw);
        agentChain = List.copyOf(agentChain);
    }

    /**
     * Returns true if the given scope was granted in this token. Comparison is case-sensitive and
     * exact.
     *
     * @param scope the scope string to check, e.g. "read:data"
     */
    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }

    /**
     * Asserts that the given scope is present in this token. Throws {@link
     * InsufficientScopeException} (HTTP 403) if the scope is not present.
     *
     * @param scope the required scope, e.g. "write:data"
     * @throws InsufficientScopeException if the scope is missing
     */
    public void requireScope(String scope) {
        if (!hasScope(scope)) {
            throw new InsufficientScopeException(scope, scopes);
        }
    }

    /**
     * Asserts that <em>every</em> scope in {@code scopes} is present in this token (logical AND).
     * Empty input is a no-op — with no required scopes the check is trivially satisfied, so callers
     * need not special-case an empty collection.
     *
     * <p>On failure throws a single {@link InsufficientScopeException} whose message names every
     * missing scope (not just the first), and whose {@link
     * InsufficientScopeException#getRequiredScopes()} carries the full requested set.
     *
     * @param scopes the required scopes; all must be present
     * @throws InsufficientScopeException if any required scope is missing
     */
    public void requireScopes(Collection<String> scopes) {
        Objects.requireNonNull(scopes, "scopes must not be null");
        if (scopes.isEmpty()) {
            return;
        }
        List<String> required = List.copyOf(scopes);
        if (required.stream().anyMatch(scope -> !hasScope(scope))) {
            throw new InsufficientScopeException(required, this.scopes);
        }
    }

    /**
     * Returns true if the raw payload contains the given claim key.
     *
     * @param claimKey the claim name, e.g. "tenant_id"
     */
    public boolean hasClaim(String claimKey) {
        return raw.containsKey(claimKey);
    }

    /**
     * Returns true if the raw payload contains the given claim key with a value that equals {@code
     * expectedValue} (using {@link Object#equals}).
     *
     * @param claimKey the claim name
     * @param expectedValue the expected value; compared with equals()
     */
    public boolean hasClaim(String claimKey, Object expectedValue) {
        return Objects.equals(raw.get(claimKey), expectedValue);
    }

    /**
     * Returns the {@code act} (actor) claim as an immutable map, or {@code null} when absent.
     *
     * <p>Present in delegation/impersonation flows (RFC 8693 token exchange with actor tokens).
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> act() {
        Object actClaim = raw.get("act");
        if (actClaim instanceof Map<?, ?> actMap) {
            return Map.copyOf((Map<String, Object>) actMap);
        }
        return null;
    }

    /**
     * Returns the {@code may_act} claim as an immutable map, or {@code null} when absent.
     *
     * <p>Indicates which actors are authorized to act on behalf of the subject.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> mayAct() {
        Object mayActClaim = raw.get("may_act");
        if (mayActClaim instanceof Map<?, ?> mayActMap) {
            return Map.copyOf((Map<String, Object>) mayActMap);
        }
        return null;
    }

    /**
     * Returns the token {@code cnf} claim as an immutable map, or an empty map when absent.
     * Modifications are unsupported and callers must not attempt to mutate the returned structure.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> cnf() {
        Object cnfClaim = raw.get("cnf");
        if (cnfClaim instanceof Map<?, ?> cnfMap) {
            return Map.copyOf((Map<String, Object>) cnfMap);
        }
        return Map.of();
    }

    /** Returns true when the token carries a {@code cnf} claim (regardless of content). */
    public boolean hasCnf() {
        return raw.get("cnf") instanceof Map<?, ?>;
    }

    /**
     * Returns true when the token carries a DPoP sender-constraining thumbprint in {@code cnf.jkt}.
     */
    public boolean isDpopBound() {
        Object jkt = cnf().get("jkt");
        return jkt instanceof String value && !value.isBlank();
    }

    /** Returns the DPoP proof key thumbprint from {@code cnf.jkt}, or {@code null} when absent. */
    public String dpopThumbprint() {
        Object jkt = cnf().get("jkt");
        return jkt instanceof String value && !value.isBlank() ? value : null;
    }
}
