package ai.authplane.sdk.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;

class AuthplaneBearerTokenResolverTest {

    private final AuthplaneBearerTokenResolver resolver = new AuthplaneBearerTokenResolver();

    private static HttpServletRequest withAuthorization(String value) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader("Authorization")).thenReturn(value);
        return req;
    }

    @Test
    void resolvesBearerScheme() {
        assertThat(resolver.resolve(withAuthorization("Bearer abc.def"))).isEqualTo("abc.def");
    }

    @Test
    void resolvesDpopScheme() {
        assertThat(resolver.resolve(withAuthorization("DPoP abc.def"))).isEqualTo("abc.def");
    }

    @Test
    void returnsNullWhenAbsentOrUnknownScheme() {
        assertThat(resolver.resolve(withAuthorization(null))).isNull();
        assertThat(resolver.resolve(withAuthorization("Basic abc"))).isNull();
    }
}
