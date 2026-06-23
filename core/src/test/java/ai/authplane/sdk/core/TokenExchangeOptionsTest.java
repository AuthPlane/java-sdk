package ai.authplane.sdk.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Coverage-focused accessor tests for {@link TokenExchangeOptions}. The integration tests exercise
 * the builder, but never call the getters in various populated/empty states; this fills that gap.
 */
class TokenExchangeOptionsTest {

    @Test
    void builder_subjectTokenNull_throwsNpe() {
        assertThatThrownBy(() -> TokenExchangeOptions.builder(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("subjectToken");
    }

    @Test
    void defaults_subjectTokenTypeIsAccessTokenUrn() {
        TokenExchangeOptions opts = TokenExchangeOptions.builder("tok").build();

        assertThat(opts.subjectToken()).isEqualTo("tok");
        assertThat(opts.subjectTokenType())
                .isEqualTo("urn:ietf:params:oauth:token-type:access_token");
        assertThat(opts.scope()).isNull();
        assertThat(opts.resources()).isNull();
        assertThat(opts.audiences()).isNull();
        assertThat(opts.resource()).isNull();
        assertThat(opts.audience()).isNull();
        assertThat(opts.actorToken()).isNull();
        assertThat(opts.actorTokenType()).isNull();
    }

    @Test
    void resource_singleValue_setsResources() {
        TokenExchangeOptions opts =
                TokenExchangeOptions.builder("tok").resource("https://api.example/x").build();

        assertThat(opts.resource()).isEqualTo("https://api.example/x");
        assertThat(opts.resources()).containsExactly("https://api.example/x");
    }

    @Test
    void resource_null_clearsResources() {
        TokenExchangeOptions opts = TokenExchangeOptions.builder("tok").resource(null).build();

        assertThat(opts.resource()).isNull();
        assertThat(opts.resources()).isNull();
    }

    @Test
    void resources_multipleValues_firstReturnedByResource() {
        TokenExchangeOptions opts =
                TokenExchangeOptions.builder("tok")
                        .resources(List.of("https://a.example", "https://b.example"))
                        .build();

        assertThat(opts.resource()).isEqualTo("https://a.example");
        assertThat(opts.resources()).containsExactly("https://a.example", "https://b.example");
    }

    @Test
    void resources_emptyList_resourceReturnsNull() {
        TokenExchangeOptions opts =
                TokenExchangeOptions.builder("tok").resources(List.of()).build();

        assertThat(opts.resource()).isNull();
        assertThat(opts.resources()).isEmpty();
    }

    @Test
    void audience_singleValue_setsAudiences() {
        TokenExchangeOptions opts = TokenExchangeOptions.builder("tok").audience("svc-a").build();

        assertThat(opts.audience()).isEqualTo("svc-a");
        assertThat(opts.audiences()).containsExactly("svc-a");
    }

    @Test
    void audience_null_clearsAudiences() {
        TokenExchangeOptions opts = TokenExchangeOptions.builder("tok").audience(null).build();

        assertThat(opts.audience()).isNull();
        assertThat(opts.audiences()).isNull();
    }

    @Test
    void audiences_multipleValues_firstReturnedByAudience() {
        TokenExchangeOptions opts =
                TokenExchangeOptions.builder("tok").audiences(List.of("svc-a", "svc-b")).build();

        assertThat(opts.audience()).isEqualTo("svc-a");
        assertThat(opts.audiences()).containsExactly("svc-a", "svc-b");
    }

    @Test
    void audiences_emptyList_audienceReturnsNull() {
        TokenExchangeOptions opts =
                TokenExchangeOptions.builder("tok").audiences(List.of()).build();

        assertThat(opts.audience()).isNull();
        assertThat(opts.audiences()).isEmpty();
    }

    @Test
    void scope_setterCopiesList() {
        List<String> scopes = List.of("read", "write");
        TokenExchangeOptions opts = TokenExchangeOptions.builder("tok").scope(scopes).build();

        assertThat(opts.scope()).containsExactly("read", "write");
    }

    @Test
    void subjectTokenType_override_isHonored() {
        TokenExchangeOptions opts =
                TokenExchangeOptions.builder("tok")
                        .subjectTokenType("urn:ietf:params:oauth:token-type:id_token")
                        .build();

        assertThat(opts.subjectTokenType()).isEqualTo("urn:ietf:params:oauth:token-type:id_token");
    }

    @Test
    void actorTokenAndType_areExposed() {
        TokenExchangeOptions opts =
                TokenExchangeOptions.builder("tok")
                        .actorToken("actor")
                        .actorTokenType("urn:ietf:params:oauth:token-type:jwt")
                        .build();

        assertThat(opts.actorToken()).isEqualTo("actor");
        assertThat(opts.actorTokenType()).isEqualTo("urn:ietf:params:oauth:token-type:jwt");
    }
}
