package ai.authplane.sdk.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.dpop.MultipleDpopProofsException;
import ai.authplane.sdk.core.errors.InsufficientScopeException;

class AuthplaneAuthenticationEntryPointTest {

    private static final String PRM_URL =
            "https://api.example.com/.well-known/oauth-protected-resource/mcp";

    private AuthplaneAuthenticationEntryPoint entryPoint() {
        return entryPoint(PRM_URL);
    }

    private AuthplaneAuthenticationEntryPoint entryPoint(String advertisedPrmUrl) {
        AuthplaneResource resource = mock(AuthplaneResource.class);
        when(resource.resourceMetadataUrl()).thenReturn(advertisedPrmUrl);
        return new AuthplaneAuthenticationEntryPoint(resource);
    }

    private static StringWriter wire(HttpServletResponse res) throws Exception {
        StringWriter body = new StringWriter();
        when(res.getWriter()).thenReturn(new PrintWriter(body));
        return body;
    }

    @Test
    void noCause_writes401MissingTokenChallenge() throws Exception {
        HttpServletResponse res = mock(HttpServletResponse.class);
        StringWriter body = wire(res);

        entryPoint().commence(mock(HttpServletRequest.class), res, null);

        verify(res).setStatus(401);
        ArgumentCaptor<String> header = ArgumentCaptor.forClass(String.class);
        verify(res).setHeader(eq("WWW-Authenticate"), header.capture());
        assertThat(header.getValue())
                .startsWith("Bearer ")
                .contains("resource_metadata=\"" + PRM_URL + "\"");
        assertThat(body.toString()).contains("\"error\":\"invalid_token\"");
    }

    @Test
    void authplaneCause_rendersThatErrorAndScheme() throws Exception {
        HttpServletResponse res = mock(HttpServletResponse.class);
        StringWriter body = wire(res);
        OAuth2AuthenticationException ex =
                new OAuth2AuthenticationException(
                        new OAuth2Error("invalid_dpop_proof"),
                        "bad",
                        new MultipleDpopProofsException("multiple DPoP headers"));

        entryPoint().commence(mock(HttpServletRequest.class), res, ex);

        verify(res).setStatus(401);
        ArgumentCaptor<String> header = ArgumentCaptor.forClass(String.class);
        verify(res).setHeader(eq("WWW-Authenticate"), header.capture());
        assertThat(header.getValue()).startsWith("DPoP ").contains("error=\"invalid_dpop_proof\"");
        assertThat(body.toString()).contains("\"error\":\"invalid_dpop_proof\"");
    }

    // -----------------------------------------------------------------------
    // resource_metadata comes from the resource's advertised URL (AS-hosted topology)
    // -----------------------------------------------------------------------

    @Test
    void configuredResourceMetadataUrl_isAdvertisedOn401() throws Exception {
        // The resource was configured with an override (authplane.resource-metadata-url), so the
        // challenge points at the AS-hosted document instead of the derived resource-hosted one.
        String asHosted = "https://auth.example.com/.well-known/oauth-protected-resource/mcp";
        HttpServletResponse res = mock(HttpServletResponse.class);
        wire(res);

        entryPoint(asHosted).commence(mock(HttpServletRequest.class), res, null);

        verify(res).setStatus(401);
        ArgumentCaptor<String> header = ArgumentCaptor.forClass(String.class);
        verify(res).setHeader(eq("WWW-Authenticate"), header.capture());
        assertThat(header.getValue()).contains("resource_metadata=\"" + asHosted + "\"");
    }

    @Test
    void insufficientScope_writes403ChallengeCarryingTheAdvertisedUrl() throws Exception {
        // The 403 challenge is rendered here too (Spring routes the authentication failure to the
        // entry point, and FailureResponse maps InsufficientScopeException to 403), so it has to
        // carry the same advertised URL as the 401.
        String asHosted = "https://auth.example.com/.well-known/oauth-protected-resource/mcp";
        HttpServletResponse res = mock(HttpServletResponse.class);
        StringWriter body = wire(res);
        OAuth2AuthenticationException ex =
                new OAuth2AuthenticationException(
                        new OAuth2Error("insufficient_scope"),
                        "forbidden",
                        new InsufficientScopeException("tools/write", List.of("tools/read")));

        entryPoint(asHosted).commence(mock(HttpServletRequest.class), res, ex);

        verify(res).setStatus(403);
        ArgumentCaptor<String> header = ArgumentCaptor.forClass(String.class);
        verify(res).setHeader(eq("WWW-Authenticate"), header.capture());
        assertThat(header.getValue())
                .startsWith("Bearer ")
                .contains("error=\"insufficient_scope\"")
                .contains("resource_metadata=\"" + asHosted + "\"");
        assertThat(body.toString()).contains("\"error\":\"insufficient_scope\"");
    }
}
