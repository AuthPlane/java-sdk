package ai.authplane.sdk.core.http;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class HttpHeadersTest {

    @Test
    void values_areCaseInsensitiveAndSkipNulls() {
        Map<String, List<String>> headers =
                Map.of("DPoP", List.of("proof-1"), "x-other", List.of("v"));
        assertThat(HttpHeaders.values(headers, "dpop")).containsExactly("proof-1");
        assertThat(HttpHeaders.values(headers, "missing")).isEmpty();
        assertThat(HttpHeaders.values(null, "dpop")).isEmpty();
    }

    @Test
    void firstValue_returnsFirstNonBlank() {
        Map<String, List<String>> headers =
                new java.util.HashMap<>(
                        Map.of("Authorization", java.util.Arrays.asList("  ", "Bearer t")));
        assertThat(HttpHeaders.firstValue(headers, "authorization")).isEqualTo("Bearer t");
    }

    @Test
    void accessToken_bearerScheme() {
        Map<String, List<String>> headers = Map.of("Authorization", List.of("Bearer abc.def.ghi"));
        assertThat(HttpHeaders.accessToken(headers)).isEqualTo("abc.def.ghi");
    }

    @Test
    void accessToken_dpopScheme() {
        Map<String, List<String>> headers = Map.of("authorization", List.of("DPoP abc.def.ghi"));
        assertThat(HttpHeaders.accessToken(headers)).isEqualTo("abc.def.ghi");
    }

    @Test
    void tokenFromAuthorization_isSchemeCaseInsensitive() {
        assertThat(HttpHeaders.tokenFromAuthorization("bearer tok")).isEqualTo("tok");
        assertThat(HttpHeaders.tokenFromAuthorization("dpop tok")).isEqualTo("tok");
    }

    @Test
    void tokenFromAuthorization_nullOrBlankOrUnknownScheme_returnsNull() {
        assertThat(HttpHeaders.tokenFromAuthorization(null)).isNull();
        assertThat(HttpHeaders.tokenFromAuthorization("Bearer   ")).isNull();
        assertThat(HttpHeaders.tokenFromAuthorization("Basic abc")).isNull();
    }

    @Test
    void accessToken_missingAuthorization_returnsNull() {
        assertThat(HttpHeaders.accessToken(Map.of("x", List.of("y")))).isNull();
    }
}
