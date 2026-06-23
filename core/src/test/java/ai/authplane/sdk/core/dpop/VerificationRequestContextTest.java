package ai.authplane.sdk.core.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class VerificationRequestContextTest {

    @Test
    void convenienceConstructor_withProofList_setsDefaultsForHeadersAndScheme() {
        VerificationRequestContext ctx =
                new VerificationRequestContext(
                        "POST", "https://api.example/resource", List.of("proof"));

        assertThat(ctx.method()).isEqualTo("POST");
        assertThat(ctx.url()).isEqualTo("https://api.example/resource");
        assertThat(ctx.dpopProofs()).containsExactly("proof");
        assertThat(ctx.dpopProof()).isEqualTo("proof");
        assertThat(ctx.headers()).isEmpty();
        assertThat(ctx.authorizationScheme()).isNull();
    }

    @Test
    void twoArgConstructor_hasNoDpopProof() {
        VerificationRequestContext ctx =
                new VerificationRequestContext("GET", "https://api.example/r");

        assertThat(ctx.dpopProofs()).isEmpty();
        assertThat(ctx.dpopProof()).isNull();
        assertThat(ctx.headers()).isEmpty();
        assertThat(ctx.authorizationScheme()).isNull();
    }

    @Test
    void fullConstructor_withHeaders_copiesMapAndExposesScheme() {
        VerificationRequestContext ctx =
                new VerificationRequestContext(
                        "GET",
                        "https://api.example/r",
                        List.of(),
                        Map.of("X-Forwarded-For", "203.0.113.5"),
                        "DPoP");

        assertThat(ctx.headers()).containsEntry("X-Forwarded-For", "203.0.113.5");
        assertThat(ctx.authorizationScheme()).isEqualTo("DPoP");
        assertThat(ctx.dpopProof()).isNull();
    }

    @Test
    void fullConstructor_nullHeaders_normalizesToEmpty() {
        VerificationRequestContext ctx =
                new VerificationRequestContext(
                        "GET", "https://api.example/r", List.of(), null, null);

        assertThat(ctx.headers()).isEmpty();
    }

    @Test
    void nullMethod_throwsNpe() {
        assertThatThrownBy(
                        () ->
                                new VerificationRequestContext(
                                        null,
                                        "https://api.example/r",
                                        List.of("p"),
                                        Map.of(),
                                        null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("method");
    }

    @Test
    void nullUrl_throwsNpe() {
        assertThatThrownBy(
                        () ->
                                new VerificationRequestContext(
                                        "GET", null, List.of("p"), Map.of(), null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("url");
    }

    @Test
    void blankMethod_throwsIllegalArgument() {
        assertThatThrownBy(
                        () ->
                                new VerificationRequestContext(
                                        "  ",
                                        "https://api.example/r",
                                        List.of("p"),
                                        Map.of(),
                                        null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("method");
    }

    @Test
    void blankUrl_throwsIllegalArgument() {
        assertThatThrownBy(
                        () ->
                                new VerificationRequestContext(
                                        "GET", "   ", List.of("p"), Map.of(), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("url");
    }

    @Test
    void headers_returnedMapIsImmutable() {
        VerificationRequestContext ctx =
                new VerificationRequestContext(
                        "GET", "https://api.example/r", List.of(), Map.of("a", "1"), null);

        assertThatThrownBy(() -> ctx.headers().put("b", "2"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void nullProofsList_throwsNpe() {
        // Pass List.of() (not null) for "no proof". Rejecting null at the ctor keeps the contract
        // consistent with the other required fields (method, url) and avoids a hidden no-op path.
        assertThatThrownBy(
                        () ->
                                new VerificationRequestContext(
                                        "GET", "https://api.example/r", (List<String>) null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("dpopProofs");
    }

    @Test
    void blankProofValues_areStripped() {
        VerificationRequestContext ctx =
                new VerificationRequestContext(
                        "GET", "https://api.example/r", Arrays.asList(null, "", "   "));

        assertThat(ctx.dpopProofs()).isEmpty();
        assertThat(ctx.dpopProof()).isNull();
    }

    @Test
    void blankProofsAroundOneRealValue_keepsOnlyTheRealOne() {
        VerificationRequestContext ctx =
                new VerificationRequestContext(
                        "GET",
                        "https://api.example/r",
                        Arrays.asList(null, "real-proof", "", "  "));

        assertThat(ctx.dpopProofs()).containsExactly("real-proof");
        assertThat(ctx.dpopProof()).isEqualTo("real-proof");
    }

    @Test
    void multipleNonBlankProofs_throwsMultipleDpopProofsException() {
        assertThatThrownBy(
                        () ->
                                new VerificationRequestContext(
                                        "POST",
                                        "https://api.example/r",
                                        List.of("proof-a", "proof-b")))
                .isInstanceOf(MultipleDpopProofsException.class)
                .hasMessageContaining("Multiple DPoP");
    }

    @Test
    void multipleNonBlankProofs_evenWithBlanksMixed_throws() {
        assertThatThrownBy(
                        () ->
                                new VerificationRequestContext(
                                        "POST",
                                        "https://api.example/r",
                                        Arrays.asList("proof-a", "", null, "proof-b")))
                .isInstanceOf(MultipleDpopProofsException.class);
    }
}
