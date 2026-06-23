package ai.authplane.sdk.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import ai.authplane.sdk.core.errors.InsufficientScopeException;

/**
 * Coverage for the helper methods on VerifiedClaims that the JWT verification happy-paths don't
 * exercise: hasScope/requireScope, hasClaim variants, act(), mayAct(), cnf(), hasCnf(),
 * isDpopBound(), dpopThumbprint(), and the null-rejection branches of the canonical constructor.
 */
class VerifiedClaimsTest {

    private static VerifiedClaims claims(Map<String, Object> raw) {
        return new VerifiedClaims(
                "sub-1",
                "client-1",
                List.of("scope:a", "scope:b"),
                "https://issuer.example",
                List.of("https://api.example"),
                100_000L,
                90_000L,
                "jti-1",
                "kid-1",
                raw,
                "",
                List.of(),
                0L);
    }

    @Test
    void hasScope_present_returnsTrue() {
        assertThat(claims(Map.of()).hasScope("scope:a")).isTrue();
    }

    @Test
    void hasScope_absent_returnsFalse() {
        assertThat(claims(Map.of()).hasScope("missing")).isFalse();
    }

    @Test
    void requireScope_present_doesNotThrow() {
        claims(Map.of()).requireScope("scope:a");
    }

    @Test
    void requireScope_absent_throwsInsufficientScope() {
        assertThatThrownBy(() -> claims(Map.of()).requireScope("missing"))
                .isInstanceOf(InsufficientScopeException.class);
    }

    @Test
    void requireScopes_empty_isNoOp() {
        claims(Map.of()).requireScopes(List.of());
    }

    @Test
    void requireScopes_allPresent_doesNotThrow() {
        claims(Map.of()).requireScopes(List.of("scope:a", "scope:b"));
    }

    @Test
    void requireScopes_someMissing_throwsNamingEveryMissingScope() {
        assertThatThrownBy(
                        () ->
                                claims(Map.of())
                                        .requireScopes(List.of("scope:a", "scope:x", "scope:y")))
                .isInstanceOf(InsufficientScopeException.class)
                .satisfies(
                        e -> {
                            var ex = (InsufficientScopeException) e;
                            assertThat(ex.getMessage()).contains("scope:x").contains("scope:y");
                            assertThat(ex.getRequiredScopes())
                                    .containsExactly("scope:a", "scope:x", "scope:y");
                        });
    }

    @Test
    void hasClaim_keyOnly_truthyForExistingKey() {
        VerifiedClaims c = claims(Map.of("tenant_id", "acme"));
        assertThat(c.hasClaim("tenant_id")).isTrue();
        assertThat(c.hasClaim("missing")).isFalse();
    }

    @Test
    void hasClaim_keyAndValue_truthyOnExactMatch() {
        VerifiedClaims c = claims(Map.of("tenant_id", "acme"));
        assertThat(c.hasClaim("tenant_id", "acme")).isTrue();
        assertThat(c.hasClaim("tenant_id", "other")).isFalse();
        assertThat(c.hasClaim("missing", "acme")).isFalse();
    }

    @Test
    void act_presentMap_returnedAsImmutableCopy() {
        VerifiedClaims c = claims(Map.of("act", Map.of("sub", "actor")));
        Map<String, Object> act = c.act();
        assertThat(act).containsEntry("sub", "actor");
        assertThatThrownBy(() -> act.put("x", "y"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void act_absent_returnsNull() {
        assertThat(claims(Map.of()).act()).isNull();
    }

    @Test
    void act_nonMap_returnsNull() {
        assertThat(claims(Map.of("act", "not-a-map")).act()).isNull();
    }

    @Test
    void mayAct_present_returnedAsImmutableCopy() {
        VerifiedClaims c = claims(Map.of("may_act", Map.of("sub", "actor")));
        assertThat(c.mayAct()).containsEntry("sub", "actor");
    }

    @Test
    void mayAct_absent_returnsNull() {
        assertThat(claims(Map.of()).mayAct()).isNull();
    }

    @Test
    void mayAct_nonMap_returnsNull() {
        assertThat(claims(Map.of("may_act", List.of("not-a-map"))).mayAct()).isNull();
    }

    @Test
    void cnf_present_returnedAsImmutableCopy() {
        VerifiedClaims c = claims(Map.of("cnf", Map.of("jkt", "thumb")));
        assertThat(c.cnf()).containsEntry("jkt", "thumb");
    }

    @Test
    void cnf_absent_returnsEmptyMap() {
        assertThat(claims(Map.of()).cnf()).isEmpty();
    }

    @Test
    void cnf_nonMap_returnsEmptyMap() {
        assertThat(claims(Map.of("cnf", "not-a-map")).cnf()).isEmpty();
    }

    @Test
    void hasCnf_truthyOnlyWhenMapValue() {
        assertThat(claims(Map.of("cnf", Map.of())).hasCnf()).isTrue();
        assertThat(claims(Map.of("cnf", "string")).hasCnf()).isFalse();
        assertThat(claims(Map.of()).hasCnf()).isFalse();
    }

    @Test
    void isDpopBound_truthyWhenJktPresent() {
        VerifiedClaims c = claims(Map.of("cnf", Map.of("jkt", "thumb")));
        assertThat(c.isDpopBound()).isTrue();
        assertThat(c.dpopThumbprint()).isEqualTo("thumb");
    }

    @Test
    void isDpopBound_falseWhenJktBlank() {
        VerifiedClaims c = claims(Map.of("cnf", Map.of("jkt", "   ")));
        assertThat(c.isDpopBound()).isFalse();
        assertThat(c.dpopThumbprint()).isNull();
    }

    @Test
    void isDpopBound_falseWhenJktNonString() {
        VerifiedClaims c = claims(Map.of("cnf", Map.of("jkt", 42)));
        assertThat(c.isDpopBound()).isFalse();
        assertThat(c.dpopThumbprint()).isNull();
    }

    @Test
    void isDpopBound_falseWhenNoCnf() {
        assertThat(claims(Map.of()).isDpopBound()).isFalse();
        assertThat(claims(Map.of()).dpopThumbprint()).isNull();
    }

    @Test
    void constructor_nullSub_throws() {
        assertThatThrownBy(
                        () ->
                                new VerifiedClaims(
                                        null,
                                        "c",
                                        List.of(),
                                        "i",
                                        List.of("a"),
                                        0L,
                                        0L,
                                        "j",
                                        "k",
                                        Map.of(),
                                        "",
                                        List.of(),
                                        0L))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("sub");
    }

    @Test
    void constructor_nullClientId_throws() {
        assertThatThrownBy(
                        () ->
                                new VerifiedClaims(
                                        "s",
                                        null,
                                        List.of(),
                                        "i",
                                        List.of("a"),
                                        0L,
                                        0L,
                                        "j",
                                        "k",
                                        Map.of(),
                                        "",
                                        List.of(),
                                        0L))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void constructor_collectionFieldsDefensivelyCopied() {
        java.util.ArrayList<String> mutableScopes = new java.util.ArrayList<>(List.of("a"));
        VerifiedClaims c =
                new VerifiedClaims(
                        "s",
                        "c",
                        mutableScopes,
                        "i",
                        List.of("aud"),
                        0L,
                        0L,
                        "j",
                        "k",
                        Map.of(),
                        "",
                        List.of(),
                        0L);
        mutableScopes.add("mutated");
        assertThat(c.scopes()).containsExactly("a");
    }
}
