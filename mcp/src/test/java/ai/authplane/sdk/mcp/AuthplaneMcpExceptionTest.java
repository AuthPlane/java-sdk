package ai.authplane.sdk.mcp;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import ai.authplane.sdk.core.errors.AuthplaneException;

class AuthplaneMcpExceptionTest {

    @Test
    void isAnAuthplaneException() {
        assertThat(new AuthplaneMcpException("boom")).isInstanceOf(AuthplaneException.class);
    }

    @Test
    void carriesMessageAndCause() {
        Throwable cause = new IllegalStateException("root");
        AuthplaneMcpException e = new AuthplaneMcpException("wrap", cause);
        assertThat(e.getMessage()).isEqualTo("wrap");
        assertThat(e.getCause()).isSameAs(cause);
    }
}
