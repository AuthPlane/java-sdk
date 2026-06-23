package ai.authplane.sdk.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Deterministic cache-key construction for token operations.
 *
 * <p>Keys are built from normalised, sorted, and Base64URL-encoded components so that logically
 * equivalent requests always map to the same cache entry.
 */
final class CacheKeys {

    private static final String DEFAULT_ACCESS_TOKEN_TYPE =
            "urn:ietf:params:oauth:token-type:access_token";

    private CacheKeys() {}

    /** Builds a stable cache key for an RFC 8693 token-exchange request. */
    static String tokenExchange(TokenExchangeOptions options) {
        String subjectTokenType = normalizeTokenType(options.subjectTokenType());
        String actorToken = normalizeValue(options.actorToken());
        String actorTokenType =
                actorToken.isEmpty() ? "" : normalizeTokenType(options.actorTokenType());

        List<String> scope = normalizeValues(options.scope());
        List<String> resources = normalizeValues(options.resources());
        List<String> audiences = normalizeValues(options.audiences());

        return String.join(
                "|",
                encodedPart("subject_token", normalizeValue(options.subjectToken())),
                encodedPart("subject_token_type", subjectTokenType),
                encodedPart("actor_token", actorToken),
                encodedPart("actor_token_type", actorTokenType),
                encodedPart("scope", String.join(" ", scope)),
                encodedPart("resources", String.join(",", resources)),
                encodedPart("audiences", String.join(",", audiences)));
    }

    /** Builds a stable cache key for an RFC 6749 client-credentials request. */
    static String clientCredentials(List<String> scopes, List<String> resources) {
        List<String> effectiveScopes = normalizeValues(scopes);
        List<String> effectiveResources = normalizeValues(resources);
        return "cc:"
                + String.join(" ", effectiveScopes)
                + ":"
                + String.join(",", effectiveResources);
    }

    static List<String> normalizeValues(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        List<String> normalized = new ArrayList<>();
        for (String value : values) {
            String trimmed = normalizeValue(value);
            if (!trimmed.isEmpty()) {
                normalized.add(trimmed);
            }
        }
        normalized.sort(String::compareTo);
        return List.copyOf(normalized);
    }

    private static String normalizeTokenType(String value) {
        String normalized = normalizeValue(value);
        return normalized.isEmpty() ? DEFAULT_ACCESS_TOKEN_TYPE : normalized;
    }

    static String normalizeValue(String value) {
        return value != null ? value.trim() : "";
    }

    private static String encodedPart(String name, String value) {
        String encoded =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(value.getBytes(StandardCharsets.UTF_8));
        return name + "=" + encoded;
    }
}
