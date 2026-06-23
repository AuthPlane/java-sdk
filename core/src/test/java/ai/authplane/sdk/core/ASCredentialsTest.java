package ai.authplane.sdk.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ASCredentialsTest {

    @Test
    void constructor_validCredentials_succeeds() {
        ASCredentials creds = new ASCredentials("my-client", "s3cret");
        assertThat(creds.clientId()).isEqualTo("my-client");
        assertThat(creds.clientSecret()).isEqualTo("s3cret");
    }

    @Test
    void constructor_nullClientId_throwsNullPointerException() {
        assertThatThrownBy(() -> new ASCredentials(null, "s3cret"))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("clientId");
    }

    @Test
    void constructor_blankClientId_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> new ASCredentials("   ", "s3cret"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("clientId");
    }

    @Test
    void constructor_emptyClientId_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> new ASCredentials("", "s3cret"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("clientId");
    }

    @Test
    void constructor_nullClientSecret_throwsNullPointerException() {
        assertThatThrownBy(() -> new ASCredentials("my-client", null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("clientSecret");
    }

    @Test
    void constructor_emptyClientSecret_succeeds() {
        // Empty secret is allowed — some AS allow empty secrets
        ASCredentials creds = new ASCredentials("my-client", "");
        assertThat(creds.clientSecret()).isEmpty();
    }

    @Test
    void authHeaders_returnsBasicHeader() {
        Map<String, String> headers = new ASCredentials("my-client", "s3cret").authHeaders();

        assertThat(headers).containsKey("Authorization");
        assertThat(headers.get("Authorization")).isEqualTo(expectedBasic("my-client", "s3cret"));
    }

    @Test
    void authHeaders_specialCharsArePercentEncoded() {
        Map<String, String> headers = new ASCredentials("client:id", "p@ss word").authHeaders();

        assertThat(headers.get("Authorization")).isEqualTo(expectedBasic("client:id", "p@ss word"));
    }

    @Test
    void toString_masksClientSecret() {
        String repr = new ASCredentials("my-client", "s3cret").toString();

        assertThat(repr).contains("my-client");
        assertThat(repr).doesNotContain("s3cret");
    }

    private static String expectedBasic(String clientId, String clientSecret) {
        String encodedId = URLEncoder.encode(clientId, StandardCharsets.UTF_8);
        String encodedSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
        return "Basic "
                + Base64.getEncoder()
                        .encodeToString(
                                (encodedId + ":" + encodedSecret).getBytes(StandardCharsets.UTF_8));
    }
}
