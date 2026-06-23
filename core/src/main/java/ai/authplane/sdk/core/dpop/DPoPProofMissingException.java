package ai.authplane.sdk.core.dpop;

import java.io.Serial;

/**
 * Thrown when DPoP validation is required but no proof was supplied.
 *
 * <p><b>Adapter contract:</b> {@code AuthplaneMcpAdapter.validateHeaders} in the {@code mcp} module
 * depends on the exact semantics of this exception type: "the token is DPoP-bound ({@code cnf.jkt}
 * present) but the call site provided no {@code VerificationRequestContext} to bind a proof
 * against." The MCP adapter swallows this specific exception in its bearer-only pre-validation pass
 * and defers proof binding to its second hook (the context extractor) — that is the Java equivalent
 * of the TS SDK's FastMCP DPoP workaround.
 *
 * <p>If you refactor {@code AuthplaneResource.validateDpop} so that this exception is thrown for a
 * <em>different</em> reason (e.g. proof present but malformed), update the swallow logic in {@code
 * AuthplaneMcpAdapter.validateHeaders} or the adapter will fail silently open for the new case.
 * Prefer adding a sibling exception type over overloading this one.
 */
public class DPoPProofMissingException extends DPoPException {

    @Serial private static final long serialVersionUID = 1L;

    public DPoPProofMissingException(String message) {
        super(message);
    }
}
