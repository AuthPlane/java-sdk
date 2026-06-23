package ai.authplane.sdk.core.fetching;

import java.util.Map;

/**
 * HTTP POST response with status code and body, used where the caller needs to inspect error
 * responses (e.g. OAuth 4xx bodies) before deciding how to react.
 *
 * <p>Package-private — used by {@link HttpTransport} and token exchange internals.
 */
public record RawPostResponse(int statusCode, String body, Map<String, String> headers) {

    public RawPostResponse {
        body = body != null ? body : "";
        headers = headers != null ? Map.copyOf(headers) : Map.of();
    }

    public String header(String name) {
        return headers.get(name.toLowerCase());
    }
}
