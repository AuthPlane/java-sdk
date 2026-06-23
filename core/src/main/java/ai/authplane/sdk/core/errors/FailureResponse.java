package ai.authplane.sdk.core.errors;

import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.jose.util.JSONObjectUtils;

import ai.authplane.sdk.core.errors.WwwAuthenticate.ChallengeOptions;

/**
 * Builds a complete, RFC-correct failure response for an {@link AuthplaneException} so adapters do
 * not hand-roll status codes, {@code WWW-Authenticate} headers, or error bodies.
 *
 * <p>Combines {@link HttpStatus#of(AuthplaneException)} (401/403/…), {@link
 * WwwAuthenticate#of(AuthplaneException, ChallengeOptions)} (correct {@code Bearer}/{@code DPoP}
 * scheme, error code, and {@code resource_metadata}), and a JSON body of the form {@code
 * {"error":"…","error_description":"…"}}.
 */
public final class FailureResponse {

    private FailureResponse() {}

    /**
     * The pieces of an HTTP failure response.
     *
     * @param status the HTTP status code
     * @param wwwAuthenticate the {@code WWW-Authenticate} challenge header value
     * @param jsonBody the JSON error body
     */
    public record Challenge(int status, String wwwAuthenticate, String jsonBody) {}

    /**
     * Builds the failure response for the given error.
     *
     * @param error the verification/authorization failure
     * @param options challenge parameters (e.g. {@code resource_metadata} URL); use {@link
     *     ChallengeOptions#empty()} when none
     * @return the status, {@code WWW-Authenticate} header, and JSON body
     */
    public static Challenge of(AuthplaneException error, ChallengeOptions options) {
        int status = HttpStatus.of(error);
        String header = WwwAuthenticate.of(error, options);
        String code = WwwAuthenticate.errorCodeFor(error);
        String description = error.getMessage() != null ? error.getMessage() : code;

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", code);
        body.put("error_description", description);

        return new Challenge(status, header, JSONObjectUtils.toJSONString(body));
    }
}
