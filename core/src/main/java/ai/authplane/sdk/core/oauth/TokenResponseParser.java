package ai.authplane.sdk.core.oauth;

import java.util.List;
import java.util.Map;

import com.nimbusds.jose.util.JSONObjectUtils;

import ai.authplane.sdk.core.TokenResponse;
import ai.authplane.sdk.core.errors.ConsentRequiredException;
import ai.authplane.sdk.core.errors.TokenExchangeException;
import ai.authplane.sdk.core.fetching.RawPostResponse;

final class TokenResponseParser {

    private TokenResponseParser() {}

    static TokenResponse parse(
            String context,
            RawPostResponse response,
            boolean allowIssuedTokenType,
            boolean expectDPoP)
            throws TokenExchangeException {
        Map<String, Object> result;
        try {
            result = JSONObjectUtils.parse(response.body());
        } catch (Exception e) {
            throw new TokenExchangeException(
                    "Failed to parse " + context + " response: " + e.getMessage(), null, e);
        }

        Object errorObj = result.get("error");
        if (errorObj instanceof String error) {
            Object descObj = result.get("error_description");
            String desc = descObj instanceof String d ? d : error;
            if ("consent_required".equals(error) || "interaction_required".equals(error)) {
                Object consentUrlObj = result.get("consent_url");
                String consentUrl = consentUrlObj instanceof String u ? u : null;
                String serviceId = firstNonBlank(result, "service_id", "service", "resource");
                if (serviceId == null) {
                    serviceId = "unknown_service";
                }
                Object causeObj = result.get("cause");
                String causeDetail = causeObj instanceof String c && !c.isBlank() ? c : desc;
                throw new ConsentRequiredException(desc, error, serviceId, causeDetail, consentUrl);
            }
            throw new TokenExchangeException(desc, error);
        }

        Object accessTokenObj = result.get("access_token");
        if (!(accessTokenObj instanceof String accessToken) || accessToken.isBlank()) {
            throw new TokenExchangeException(context + " response missing 'access_token'", null);
        }

        String tokenType = parseTokenType(result.get("token_type"));

        if (expectDPoP && !"DPoP".equals(tokenType)) {
            throw new TokenExchangeException(
                    "DPoP proof was sent but response token_type is '"
                            + tokenType
                            + "' instead of 'DPoP'; the token is not sender-constrained",
                    null);
        }

        Integer expiresIn = parseExpiresIn(result.get("expires_in"), context);

        Object scopeObj = result.get("scope");
        List<String> scopes = null;
        if (scopeObj instanceof String scopeStr && !scopeStr.isBlank()) {
            scopes = List.of(scopeStr.split(" "));
        }

        String issuedTokenType = null;
        if (allowIssuedTokenType) {
            issuedTokenType = result.get("issued_token_type") instanceof String itt ? itt : null;
            if (issuedTokenType == null || issuedTokenType.isBlank()) {
                throw new TokenExchangeException(
                        context
                                + " response missing required 'issued_token_type' (RFC 8693 §2.2.1)",
                        null);
            }
        }

        return new TokenResponse(accessToken, tokenType, expiresIn, scopes, issuedTokenType);
    }

    private static String parseTokenType(Object tokenTypeObj) throws TokenExchangeException {
        if (!(tokenTypeObj instanceof String tokenType) || tokenType.isBlank()) {
            return "Bearer";
        }
        if ("bearer".equalsIgnoreCase(tokenType)) {
            return "Bearer";
        }
        if ("dpop".equalsIgnoreCase(tokenType)) {
            return "DPoP";
        }
        throw new TokenExchangeException(
                "Unsupported token_type '" + tokenType + "'; only Bearer and DPoP are supported",
                null);
    }

    private static Integer parseExpiresIn(Object expiresInObj, String context)
            throws TokenExchangeException {
        if (expiresInObj == null) {
            return null;
        }
        if (!(expiresInObj instanceof Number number)) {
            throw new TokenExchangeException(
                    context + " response has invalid 'expires_in' value", null);
        }

        int expiresIn = number.intValue();
        if (expiresIn < 0) {
            throw new TokenExchangeException(
                    context + " response has negative 'expires_in' value", null);
        }
        return expiresIn;
    }

    private static String firstNonBlank(Map<String, Object> source, String... keys) {
        for (String key : keys) {
            Object value = source.get(key);
            if (value instanceof String s && !s.isBlank()) {
                return s;
            }
        }
        return null;
    }
}
