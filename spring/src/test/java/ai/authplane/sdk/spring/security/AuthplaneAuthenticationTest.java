package ai.authplane.sdk.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import ai.authplane.sdk.core.VerifiedClaims;
import ai.authplane.sdk.core.errors.InsufficientScopeException;

class AuthplaneAuthenticationTest {

    static final VerifiedClaims CLAIMS =
            new VerifiedClaims(
                    "user-sub",
                    "client-id",
                    List.of("tools/read", "tools/write"),
                    "https://auth.example.com",
                    List.of("https://api.example.com"),
                    System.currentTimeMillis() / 1000 + 3600,
                    System.currentTimeMillis() / 1000,
                    "jti-001",
                    "key-1",
                    Map.of("tenant", "acme"),
                    "",
                    List.of(),
                    0L);

    static final String RAW_TOKEN = "raw.jwt.token";

    @BeforeEach
    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    // -----------------------------------------------------------------------
    // Construction and AbstractAuthenticationToken contract
    // -----------------------------------------------------------------------

    @Test
    void of_setsAuthenticatedTrue() {
        AuthplaneAuthentication auth = AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN);
        assertThat(auth.isAuthenticated()).isTrue();
    }

    @Test
    void getCredentials_returnsEmptyString() {
        assertThat(AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).getCredentials()).isEqualTo("");
    }

    @Test
    void getPrincipal_returnsSub() {
        assertThat(AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).getPrincipal())
                .isEqualTo("user-sub");
    }

    @Test
    void getName_returnsSub() {
        assertThat(AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).getName()).isEqualTo("user-sub");
    }

    @Test
    void getAuthorities_returnsScopePrefixedAuthorities() {
        var authorities =
                AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList();
        assertThat(authorities).containsExactlyInAnyOrder("SCOPE_tools/read", "SCOPE_tools/write");
    }

    @Test
    void getToken_exposesRawAccessToken() {
        var token = AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).getToken();
        assertThat(token.getTokenValue()).isEqualTo(RAW_TOKEN);
        assertThat(token.getTokenType())
                .isEqualTo(
                        org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType
                                .BEARER);
    }

    @Test
    void getTokenAttributes_returnsRawClaims() {
        assertThat(AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).getTokenAttributes())
                .containsEntry("tenant", "acme");
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    @Test
    void getClaims_returnsWrappedClaims() {
        assertThat(AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).getClaims()).isSameAs(CLAIMS);
    }

    @Test
    void getSubject_returnsSub() {
        assertThat(AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).getSubject())
                .isEqualTo("user-sub");
    }

    @Test
    void getClientId_returnsClientId() {
        assertThat(AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).getClientId())
                .isEqualTo("client-id");
    }

    @Test
    void getScopes_returnsScopeList() {
        assertThat(AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).getScopes())
                .containsExactly("tools/read", "tools/write");
    }

    @Test
    void getClaim_existingKey_returnsValue() {
        assertThat(AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).getClaim("tenant"))
                .isEqualTo("acme");
    }

    @Test
    void getClaim_missingKey_returnsNull() {
        assertThat(AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).getClaim("nonexistent")).isNull();
    }

    @Test
    void getRawClaims_returnsRawMap() {
        assertThat(AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).getRawClaims())
                .containsEntry("tenant", "acme");
    }

    // -----------------------------------------------------------------------
    // requireScope / hasScope
    // -----------------------------------------------------------------------

    @Test
    void requireScope_presentScope_doesNotThrow() {
        AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).requireScope("tools/read");
    }

    @Test
    void requireScope_missingScope_throwsAccessDeniedException() {
        assertThatThrownBy(
                        () ->
                                AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN)
                                        .requireScope("tools/admin"))
                .isInstanceOf(AccessDeniedException.class)
                .hasCauseInstanceOf(InsufficientScopeException.class);
    }

    @Test
    void hasScope_presentScope_returnsTrue() {
        assertThat(AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).hasScope("tools/write")).isTrue();
    }

    @Test
    void hasScope_missingScope_returnsFalse() {
        assertThat(AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).hasScope("tools/delete"))
                .isFalse();
    }

    // -----------------------------------------------------------------------
    // requireAllScopes / hasAllScopes
    // -----------------------------------------------------------------------

    @Test
    void requireAllScopes_allPresent_doesNotThrow() {
        AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN).requireAllScopes("tools/read", "tools/write");
    }

    @Test
    void requireAllScopes_oneAbsent_throwsAccessDeniedException() {
        assertThatThrownBy(
                        () ->
                                AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN)
                                        .requireAllScopes("tools/read", "tools/delete"))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void requireAllScopes_severalAbsent_namesEveryMissingScope() {
        // Regression: the old loop threw on the first miss, so the 403 named only one scope.
        assertThatThrownBy(
                        () ->
                                AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN)
                                        .requireAllScopes("tools/admin", "tools/delete"))
                .isInstanceOf(AccessDeniedException.class)
                .hasCauseInstanceOf(InsufficientScopeException.class)
                .hasMessageContaining("tools/admin")
                .hasMessageContaining("tools/delete");
    }

    @Test
    void hasAllScopes_allPresent_returnsTrue() {
        assertThat(
                        AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN)
                                .hasAllScopes("tools/read", "tools/write"))
                .isTrue();
    }

    @Test
    void hasAllScopes_oneAbsent_returnsFalse() {
        assertThat(
                        AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN)
                                .hasAllScopes("tools/read", "tools/delete"))
                .isFalse();
    }

    // -----------------------------------------------------------------------
    // current() — SecurityContextHolder integration
    // -----------------------------------------------------------------------

    @Test
    void current_whenSetInContext_returnsAuthentication() {
        AuthplaneAuthentication auth = AuthplaneAuthentication.of(CLAIMS, RAW_TOKEN);
        var ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(auth);
        SecurityContextHolder.setContext(ctx);

        assertThat(AuthplaneAuthentication.current()).isSameAs(auth);
    }

    @Test
    void current_whenNotInContext_throwsIllegalStateException() {
        assertThatThrownBy(AuthplaneAuthentication::current)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No AuthplaneAuthentication");
    }

    @Test
    void current_whenWrongTypeInContext_throwsIllegalStateException() {
        var ctx = SecurityContextHolder.createEmptyContext();
        // Set a non-AuthplaneAuthentication token
        ctx.setAuthentication(new UsernamePasswordAuthenticationToken("user", "pass"));
        SecurityContextHolder.setContext(ctx);

        assertThatThrownBy(AuthplaneAuthentication::current)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("UsernamePasswordAuthenticationToken");
    }
}
