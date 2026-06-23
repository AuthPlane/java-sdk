package ai.authplane.sdk.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;

class TokenResponseTest {

    @Test
    void constructor_setsAllFields() {
        TokenResponse r =
                new TokenResponse("at", "Bearer", 3600, List.of("read"), "urn:token-type");
        assertThat(r.accessToken()).isEqualTo("at");
        assertThat(r.tokenType()).isEqualTo("Bearer");
        assertThat(r.expiresIn()).isEqualTo(3600);
        assertThat(r.scopes()).containsExactly("read");
        assertThat(r.issuedTokenType()).isEqualTo("urn:token-type");
    }

    @Test
    void scopes_areDefensivelyCopied() {
        List<String> mutable = new java.util.ArrayList<>(List.of("a"));
        TokenResponse r = new TokenResponse("at", "Bearer", null, mutable, null);
        mutable.add("b");
        assertThat(r.scopes()).containsExactly("a");
    }

    @Test
    void scopes_areImmutable() {
        TokenResponse r = new TokenResponse("at", "Bearer", null, List.of("read"), null);
        assertThatThrownBy(() -> r.scopes().add("write"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void scopes_nullStaysNull() {
        TokenResponse r = new TokenResponse("at", "Bearer", null, null, null);
        assertThat(r.scopes()).isNull();
    }
}
