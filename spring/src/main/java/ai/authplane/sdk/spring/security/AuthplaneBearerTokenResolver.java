package ai.authplane.sdk.spring.security;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;

import ai.authplane.sdk.core.http.HttpHeaders;

/**
 * {@link BearerTokenResolver} that extracts the access token from the {@code Authorization} header
 * under both the {@code Bearer} and (RFC 9449) {@code DPoP} schemes, so DPoP-bound tokens presented
 * with the {@code DPoP} scheme are accepted. Returns {@code null} when no usable token is present
 * (no exception), letting the chain fall through to the entry point.
 */
final class AuthplaneBearerTokenResolver implements BearerTokenResolver {

    @Override
    public String resolve(HttpServletRequest request) {
        return HttpHeaders.tokenFromAuthorization(request.getHeader("Authorization"));
    }
}
