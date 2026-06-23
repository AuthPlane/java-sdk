package ai.authplane.sdk.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.dpop.MultipleDpopProofsException;

class AuthplaneAuthenticationEntryPointTest {

    private static final String PRM_URL =
            "https://api.example.com/.well-known/oauth-protected-resource/mcp";

    private AuthplaneAuthenticationEntryPoint entryPoint() {
        AuthplaneResource resource = mock(AuthplaneResource.class);
        when(resource.prmUrl()).thenReturn(PRM_URL);
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
}
