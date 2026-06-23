package ai.authplane.sdk.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.VerificationResult;
import ai.authplane.sdk.core.VerifiedClaims;
import ai.authplane.sdk.core.dpop.DPoPBindingMismatchException;
import ai.authplane.sdk.core.dpop.VerificationRequestContext;
import ai.authplane.sdk.core.errors.InvalidClaimsException;
import ai.authplane.sdk.core.errors.TokenExpiredException;

@ExtendWith(MockitoExtension.class)
class AuthplaneAuthenticationProviderTest {

    @Mock AuthplaneResource verifier;

    AuthplaneAuthenticationProvider provider;

    final VerifiedClaims validClaims =
            new VerifiedClaims(
                    "user-sub",
                    "client-id",
                    List.of("tools/read"),
                    "https://auth.example.com",
                    List.of("https://api.example.com"),
                    System.currentTimeMillis() / 1000 + 3600,
                    System.currentTimeMillis() / 1000,
                    "jti-001",
                    "key-1",
                    Map.of(),
                    "",
                    List.of(),
                    0L);

    @BeforeEach
    void setUp() {
        provider = new AuthplaneAuthenticationProvider(verifier);
    }

    private static AuthplanePreAuthToken request(String token) {
        return new AuthplanePreAuthToken(
                token, new VerificationRequestContext("GET", "https://api.example.com/mcp"));
    }

    // -----------------------------------------------------------------------
    // Constructor / supports
    // -----------------------------------------------------------------------

    @Test
    void constructor_nullVerifier_throwsNPE() {
        assertThatThrownBy(() -> new AuthplaneAuthenticationProvider(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void supports_preAuthTokenType_returnsTrue() {
        assertThat(provider.supports(AuthplanePreAuthToken.class)).isTrue();
    }

    @Test
    void supports_otherType_returnsFalse() {
        assertThat(provider.supports(UsernamePasswordAuthenticationToken.class)).isFalse();
    }

    @Test
    void authenticate_unsupportedType_returnsNull() {
        // Spring's AuthenticationProvider contract: return null for tokens this provider can't
        // handle so a ProviderManager delegates to the next provider, rather than
        // ClassCastException.
        Authentication other = new UsernamePasswordAuthenticationToken("u", "p");
        assertThat(provider.authenticate(other)).isNull();
    }

    // -----------------------------------------------------------------------
    // authenticate() — happy path (token + request context)
    // -----------------------------------------------------------------------

    @Test
    void authenticate_validToken_returnsAuthplaneAuthentication() {
        when(verifier.verify(eq("good-token"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.completedFuture(VerificationResult.bearer(validClaims)));

        var result = provider.authenticate(request("good-token"));

        assertThat(result).isInstanceOf(AuthplaneAuthentication.class);
        AuthplaneAuthentication auth = (AuthplaneAuthentication) result;
        assertThat(auth.isAuthenticated()).isTrue();
        assertThat(auth.getClaims()).isSameAs(validClaims);
    }

    // -----------------------------------------------------------------------
    // authenticate() — failure mapping
    // -----------------------------------------------------------------------

    @Test
    void authenticate_completionExceptionWithAuthplaneCause_throwsOAuth2Exception() {
        when(verifier.verify(eq("bad-token"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(
                                        new InvalidClaimsException("issuer mismatch"))));

        assertThatThrownBy(() -> provider.authenticate(request("bad-token")))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("issuer mismatch");
    }

    @Test
    void authenticate_expiredToken_throwsOAuth2Exception() {
        when(verifier.verify(eq("expired"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(new TokenExpiredException("expired"))));

        assertThatThrownBy(() -> provider.authenticate(request("expired")))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void authenticate_completionExceptionWithNullCause_throwsOAuth2Exception() {
        when(verifier.verify(eq("bad-token"), any(VerificationRequestContext.class)))
                .thenReturn(CompletableFuture.failedFuture(new CompletionException(null)));

        assertThatThrownBy(() -> provider.authenticate(request("bad-token")))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void authenticate_errorWithNullMessage_usesDefaultDescription() {
        when(verifier.verify(eq("bad-token"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(new InvalidClaimsException(null))));

        assertThatThrownBy(() -> provider.authenticate(request("bad-token")))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("Token validation failed");
    }

    @Test
    void authenticate_nonAuthplaneCause_doesNotLeakMessage() {
        when(verifier.verify(eq("bad-token"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(
                                        new RuntimeException(
                                                "internal db url: jdbc://user:secret@host/db"))));

        OAuth2AuthenticationException thrown =
                org.assertj.core.api.Assertions.catchThrowableOfType(
                        () -> provider.authenticate(request("bad-token")),
                        OAuth2AuthenticationException.class);

        assertThat(thrown).isNotNull();
        assertThat(thrown.getMessage()).doesNotContain("secret");
        assertThat(thrown.getError().getDescription()).isEqualTo("Token validation failed");
        assertThat(thrown.getError().getErrorCode()).isEqualTo("invalid_token");
    }

    @Test
    void authenticate_directAuthplaneException_throwsOAuth2Exception() {
        when(verifier.verify(eq("direct-fail"), any(VerificationRequestContext.class)))
                .thenThrow(new InvalidClaimsException("synchronous failure"));

        assertThatThrownBy(() -> provider.authenticate(request("direct-fail")))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("synchronous failure");
    }

    @Test
    void authenticate_dpopBindingMismatch_throwsOAuth2Exception() {
        when(verifier.verify(eq("bound-token"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(
                                        new DPoPBindingMismatchException(
                                                "proof binding mismatch"))));

        assertThatThrownBy(() -> provider.authenticate(request("bound-token")))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("binding mismatch");
    }
}
