package ai.authplane.sdk.core.dpop;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * SDK-defined HTTP request context for optional inbound DPoP validation.
 *
 * <p>Adapters collect the raw {@code DPoP} header values from their framework (Jakarta servlet,
 * Spring {@code ServerRequest}, Vert.x, Helidon, plain Netty, …) and pass them as a {@link List};
 * RFC 9449 §4.3 #1 ("there is not more than one {@code DPoP} HTTP request header field") is
 * enforced at construction so the verifier never sees a structurally ambiguous request.
 * Post-construction the list is guaranteed to hold zero or one non-blank entries.
 *
 * @param method HTTP method associated with the protected-resource request
 * @param url absolute protected-resource request URL
 * @param dpopProofs raw {@code DPoP} header values from the request (must not be null — pass {@link
 *     List#of()} when the request carries no DPoP proof). At most one non-blank entry survives
 *     normalization; passing more than one non-blank value throws {@link
 *     MultipleDpopProofsException} (RFC 9449 §4.3 #1)
 * @param headers request headers, if the caller wants to retain them alongside verification
 * @param authorizationScheme authorization scheme metadata such as {@code DPoP} or {@code Bearer},
 *     nullable
 */
public record VerificationRequestContext(
        String method,
        String url,
        List<String> dpopProofs,
        Map<String, String> headers,
        String authorizationScheme) {

    /**
     * Validates method/url and enforces RFC 9449 §4.3 #1 on the DPoP header values. The compact
     * constructor rejects {@code null} for {@code dpopProofs} (callers must pass {@link List#of()}
     * for "no proof"), filters {@code null} and blank entries within the list, and throws {@link
     * MultipleDpopProofsException} when more than one non-blank value is present.
     */
    public VerificationRequestContext {
        Objects.requireNonNull(method, "method must not be null");
        Objects.requireNonNull(url, "url must not be null");
        Objects.requireNonNull(dpopProofs, "dpopProofs must not be null (use List.of() for none)");
        if (method.isBlank()) {
            throw new IllegalArgumentException("method must not be blank");
        }
        if (url.isBlank()) {
            throw new IllegalArgumentException("url must not be blank");
        }
        dpopProofs = normalizeDpopProofs(dpopProofs);
        headers = headers != null ? Map.copyOf(headers) : Map.of();
    }

    /** Convenience constructor for the common method/url/proofs case. */
    public VerificationRequestContext(String method, String url, List<String> dpopProofs) {
        this(method, url, dpopProofs, Map.of(), null);
    }

    /** Convenience constructor for requests with no inbound DPoP context. */
    public VerificationRequestContext(String method, String url) {
        this(method, url, List.of(), Map.of(), null);
    }

    /**
     * Returns the single normalized DPoP proof, or {@code null} when the request carried none. The
     * compact constructor guarantees the underlying list holds at most one entry.
     */
    public String dpopProof() {
        return dpopProofs.isEmpty() ? null : dpopProofs.get(0);
    }

    /**
     * Enforces RFC 9449 §4.3 #1 ("there is not more than one {@code DPoP} HTTP request header
     * field") on a raw header-value list and returns a normalized list holding at most one
     * non-blank entry. {@code null} and blank entries are filtered; a second non-blank value throws
     * {@link MultipleDpopProofsException}.
     *
     * <p>Intended for adapter early-rejection gates that don't have HTTP method/URL on hand and
     * therefore cannot build a full {@link VerificationRequestContext} (which performs the same
     * check at construction). Direct callers that hold a method/URL should pass the raw list to the
     * constructor instead of pre-normalizing.
     *
     * @param raw raw {@code DPoP} header values from the framework (may not be {@code null}; pass
     *     {@link List#of()} when the request carries no DPoP header)
     * @return immutable list of zero or one non-blank entries
     * @throws MultipleDpopProofsException when {@code raw} carries more than one non-blank entry
     */
    public static List<String> assertSingleDpopHeader(List<String> raw) {
        Objects.requireNonNull(raw, "raw must not be null (use List.of() for none)");
        return normalizeDpopProofs(raw);
    }

    private static List<String> normalizeDpopProofs(List<String> raw) {
        if (raw.isEmpty()) {
            return List.of();
        }
        String found = null;
        for (String value : raw) {
            if (value == null || value.isBlank()) {
                continue;
            }
            if (found != null) {
                throw new MultipleDpopProofsException("Multiple DPoP headers are not allowed");
            }
            found = value;
        }
        return found == null ? List.of() : List.of(found);
    }
}
