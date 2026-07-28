package ai.authplane.sdk.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class IdentifiersTest {

    @Test
    void validIdentifiers_returnedUnchanged() {
        // Trailing slashes, host case, and explicit ports are legal variations — preserved.
        for (String value :
                java.util.List.of(
                        "https://auth.example.com",
                        "https://auth.example.com/",
                        "https://auth.example.com/tenant/",
                        "https://Auth.Example.com:443/t1",
                        "http://localhost:8080/issuer")) {
            assertThat(Identifiers.requireValidIdentifier(value, "issuer")).isSameAs(value);
        }
    }

    @Test
    void nonHttpScheme_rejected() {
        assertThatThrownBy(
                        () -> Identifiers.requireValidIdentifier("ftp://x.example.com", "issuer"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("http");
    }

    @Test
    void missingScheme_rejected() {
        assertThatThrownBy(() -> Identifiers.requireValidIdentifier("auth.example.com", "issuer"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void missingAuthority_rejected() {
        assertThatThrownBy(() -> Identifiers.requireValidIdentifier("https:example.com", "issuer"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("authority");
    }

    @Test
    void fragment_rejected() {
        // RFC 8707 §2 — resource identifiers must not contain a fragment.
        assertThatThrownBy(
                        () ->
                                Identifiers.requireValidIdentifier(
                                        "https://api.example.com/mcp#frag", "resourceUri"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("fragment");
    }
}
