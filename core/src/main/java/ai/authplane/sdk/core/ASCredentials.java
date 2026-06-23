package ai.authplane.sdk.core;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

/**
 * Static client credentials for the Authorization Server.
 *
 * <p>Used by the RFC 6749 client-credentials grant, RFC 7662 introspection, RFC 8693 token
 * exchange, and RFC 7009 revocation. Implements {@link AuthProvider} directly: {@link
 * #authHeaders()} emits an HTTP Basic {@code Authorization} header (RFC 6749 §2.3.1), with the
 * {@code client_id} and {@code client_secret} form-urlencoded before being Base64-encoded. Supply
 * it anywhere an {@link AuthProvider} is expected.
 *
 * @see AuthplaneClientBuilder#authProvider(AuthProvider)
 */
public record ASCredentials(String clientId, String clientSecret) implements AuthProvider {

    /** Validates that clientId is non-null and non-blank, and clientSecret is non-null. */
    public ASCredentials {
        Objects.requireNonNull(clientId, "clientId must not be null");
        if (clientId.isBlank()) throw new IllegalArgumentException("clientId must not be blank");
        Objects.requireNonNull(clientSecret, "clientSecret must not be null");
    }

    @Override
    public Map<String, String> authHeaders() {
        String encodedId = URLEncoder.encode(clientId, StandardCharsets.UTF_8);
        String encodedSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
        String basic =
                Base64.getEncoder()
                        .encodeToString(
                                (encodedId + ":" + encodedSecret).getBytes(StandardCharsets.UTF_8));
        return Map.of("Authorization", "Basic " + basic);
    }

    /**
     * Returns a representation that masks the client secret, so credentials are never exposed in
     * logs, exception messages, or debugger output. Overrides the record-generated {@code toString}
     * which would otherwise print {@code clientSecret} in plaintext.
     */
    @Override
    public String toString() {
        return "ASCredentials[clientId=" + clientId + ", clientSecret=***]";
    }
}
