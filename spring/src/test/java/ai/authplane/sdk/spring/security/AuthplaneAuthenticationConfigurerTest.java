package ai.authplane.sdk.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.throwable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.DefaultSecurityFilterChain;

import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.dpop.MultipleDpopProofsException;
import ai.authplane.sdk.spring.security.AuthplaneAuthenticationConfigurer.RequestContextAuthenticationManagerResolver;

class AuthplaneAuthenticationConfigurerTest {

    private static final ObjectPostProcessor<Object> NO_OP_POST_PROCESSOR =
            new ObjectPostProcessor<>() {
                @Override
                public <O> O postProcess(O object) {
                    return object;
                }
            };

    @Test
    void addsBearerTokenAuthenticationFilterToChain() throws Exception {
        AuthplaneResource resource = mock(AuthplaneResource.class);
        GenericApplicationContext context = new GenericApplicationContext();
        context.refresh();
        Map<Class<?>, Object> sharedObjects = new HashMap<>();
        sharedObjects.put(ApplicationContext.class, context);
        HttpSecurity http =
                new HttpSecurity(
                        NO_OP_POST_PROCESSOR,
                        new AuthenticationManagerBuilder(NO_OP_POST_PROCESSOR),
                        sharedObjects);
        AuthenticationManager passthrough = authentication -> authentication;

        DefaultSecurityFilterChain chain =
                http.authenticationManager(passthrough)
                        .with(
                                new AuthplaneAuthenticationConfigurer(resource),
                                Customizer.withDefaults())
                        .build();

        assertThat(chain.getFilters()).anyMatch(f -> f instanceof BearerTokenAuthenticationFilter);
    }

    // -----------------------------------------------------------------------
    // RequestContextAuthenticationManagerResolver — builds the per-request
    // VerificationRequestContext (method + DPoP proofs from the request; htu
    // via resource.normalizeRequestUrl) and delegates to the provider with an
    // AuthplanePreAuthToken.
    // -----------------------------------------------------------------------

    private static final String HTU = "https://api.example.com/mcp";

    private static HttpServletRequest request(String method, List<String> dpopHeaders) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn(method);
        // An internal/proxy-facing request URL; the resolver re-anchors it via normalizeRequestUrl.
        when(req.getRequestURL()).thenReturn(new StringBuffer("http://internal-host:8080/mcp"));
        when(req.getHeaders("DPoP"))
                .thenReturn(dpopHeaders == null ? null : Collections.enumeration(dpopHeaders));
        return req;
    }

    private static AuthplaneResource resourceReturning(String htu) {
        AuthplaneResource resource = mock(AuthplaneResource.class);
        when(resource.normalizeRequestUrl(anyString())).thenReturn(htu);
        return resource;
    }

    @Test
    void resolver_buildsContextWithDpopProof_andDelegatesToProvider() {
        AuthplaneAuthenticationProvider provider = mock(AuthplaneAuthenticationProvider.class);
        Authentication authenticated = mock(Authentication.class);
        when(provider.authenticate(any())).thenReturn(authenticated);

        var resolver =
                new RequestContextAuthenticationManagerResolver(provider, resourceReturning(HTU));
        AuthenticationManager manager = resolver.resolve(request("POST", List.of("proof-jwt")));

        Authentication result = manager.authenticate(new BearerTokenAuthenticationToken("tok-123"));

        assertThat(result).isSameAs(authenticated);
        ArgumentCaptor<AuthplanePreAuthToken> captor =
                ArgumentCaptor.forClass(AuthplanePreAuthToken.class);
        verify(provider).authenticate(captor.capture());
        AuthplanePreAuthToken preAuth = captor.getValue();
        assertThat(preAuth.token()).isEqualTo("tok-123");
        assertThat(preAuth.context().method()).isEqualTo("POST");
        // htu is the resource-anchored URL from normalizeRequestUrl, not the servlet request URL.
        assertThat(preAuth.context().url()).isEqualTo(HTU);
        assertThat(preAuth.context().dpopProofs()).containsExactly("proof-jwt");
    }

    @Test
    void resolver_noDpopHeader_buildsContextWithEmptyProofs() {
        AuthplaneAuthenticationProvider provider = mock(AuthplaneAuthenticationProvider.class);
        when(provider.authenticate(any())).thenReturn(mock(Authentication.class));

        var resolver =
                new RequestContextAuthenticationManagerResolver(provider, resourceReturning(HTU));
        resolver.resolve(request("GET", null))
                .authenticate(new BearerTokenAuthenticationToken("tok-456"));

        ArgumentCaptor<AuthplanePreAuthToken> captor =
                ArgumentCaptor.forClass(AuthplanePreAuthToken.class);
        verify(provider).authenticate(captor.capture());
        assertThat(captor.getValue().context().dpopProofs()).isEmpty();
    }

    @Test
    void resolver_multipleDpopHeaders_throwsOAuth2ExceptionWithInvalidDpopProof() {
        // RFC 9449 §4.3 #1 is enforced at VerificationRequestContext construction inside the
        // resolver, before the provider is invoked. The resolver maps the typed exception to an
        // OAuth2AuthenticationException (an AuthenticationException) so the surrounding
        // BearerTokenAuthenticationFilter — which only catches AuthenticationException — routes it
        // to the entry point as a 401 DPoP challenge instead of letting it escape as a 500. The
        // original MultipleDpopProofsException is preserved as the cause so the entry point renders
        // the right scheme/code.
        AuthplaneAuthenticationProvider provider = mock(AuthplaneAuthenticationProvider.class);

        var resolver =
                new RequestContextAuthenticationManagerResolver(provider, resourceReturning(HTU));
        AuthenticationManager manager =
                resolver.resolve(request("POST", List.of("proof-1", "proof-2")));

        assertThatThrownBy(
                        () -> manager.authenticate(new BearerTokenAuthenticationToken("tok-789")))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasCauseInstanceOf(MultipleDpopProofsException.class)
                .asInstanceOf(throwable(OAuth2AuthenticationException.class))
                .extracting(e -> e.getError().getErrorCode())
                .isEqualTo("invalid_dpop_proof");
        verifyNoInteractions(provider);
    }
}
