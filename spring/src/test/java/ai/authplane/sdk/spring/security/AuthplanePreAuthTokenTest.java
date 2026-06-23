package ai.authplane.sdk.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import ai.authplane.sdk.core.dpop.VerificationRequestContext;

class AuthplanePreAuthTokenTest {

    private static final VerificationRequestContext CONTEXT =
            new VerificationRequestContext("POST", "https://api.example.com/mcp");

    @Test
    void exposesTokenAndContext() {
        AuthplanePreAuthToken token = new AuthplanePreAuthToken("tok-abc", CONTEXT);

        assertThat(token.token()).isEqualTo("tok-abc");
        assertThat(token.context()).isSameAs(CONTEXT);
    }

    @Test
    void credentialsAreTheRawToken() {
        AuthplanePreAuthToken token = new AuthplanePreAuthToken("tok-abc", CONTEXT);

        assertThat(token.getCredentials()).isEqualTo("tok-abc");
    }

    @Test
    void principalIsSentinel_notTheToken_soItDoesNotLeak() {
        AuthplanePreAuthToken token = new AuthplanePreAuthToken("super-secret-token", CONTEXT);

        // Principal must not be the raw token — it surfaces via toString()/auth-failure events.
        assertThat(token.getPrincipal()).isNotEqualTo("super-secret-token");
        assertThat(token.getPrincipal().toString()).doesNotContain("super-secret-token");
        assertThat(token.toString()).doesNotContain("super-secret-token");
    }

    @Test
    void isUnauthenticatedOnConstruction() {
        AuthplanePreAuthToken token = new AuthplanePreAuthToken("tok-abc", CONTEXT);

        assertThat(token.isAuthenticated()).isFalse();
    }
}
