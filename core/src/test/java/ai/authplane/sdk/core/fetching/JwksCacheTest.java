package ai.authplane.sdk.core.fetching;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import org.junit.jupiter.api.Test;

/**
 * Coverage for JwksCache's key-by-kid lookup including the "kid not found", "no keys array", and
 * "key filtered by use/key_ops" branches that the happy-path AuthplaneClient tests don't exercise.
 */
class JwksCacheTest {

    private static JwksCache cacheWith(Map<String, Object> jwks) {
        DocumentFetcher fetcher =
                url -> CompletableFuture.completedFuture(new FetchResult(jwks, null));
        return new JwksCache(fetcher, "https://example.com/jwks", 300, null);
    }

    @Test
    void getKeyByKid_keyPresent_returnsKey() throws Exception {
        JwksCache cache =
                cacheWith(
                        Map.of(
                                "keys",
                                List.of(
                                        Map.of(
                                                "kty", "RSA",
                                                "kid", "k1",
                                                "use", "sig"))));

        Optional<Map<String, Object>> key = cache.getKeyByKid("k1", false);

        assertThat(key).isPresent();
        assertThat(key.get().get("kid")).isEqualTo("k1");
    }

    @Test
    void getKeyByKid_kidNotPresent_returnsEmpty() throws Exception {
        JwksCache cache =
                cacheWith(
                        Map.of(
                                "keys",
                                List.of(Map.of("kty", "RSA", "kid", "other", "use", "sig"))));

        Optional<Map<String, Object>> key = cache.getKeyByKid("missing", false);

        assertThat(key).isEmpty();
    }

    @Test
    void getKeyByKid_documentMissingKeysArray_returnsEmpty() throws Exception {
        JwksCache cache = cacheWith(Map.of("notKeys", List.of()));

        Optional<Map<String, Object>> key = cache.getKeyByKid("k1", false);

        assertThat(key).isEmpty();
    }

    @Test
    void getKeyByKid_useEnc_filteredOut() throws Exception {
        JwksCache cache =
                cacheWith(Map.of("keys", List.of(Map.of("kty", "RSA", "kid", "k1", "use", "enc"))));

        Optional<Map<String, Object>> key = cache.getKeyByKid("k1", false);

        assertThat(key).isEmpty();
    }

    @Test
    void getKeyByKid_keyOpsWithoutVerify_filteredOut() throws Exception {
        JwksCache cache =
                cacheWith(
                        Map.of(
                                "keys",
                                List.of(
                                        Map.of(
                                                "kty", "RSA",
                                                "kid", "k1",
                                                "key_ops", List.of("sign")))));

        Optional<Map<String, Object>> key = cache.getKeyByKid("k1", false);

        assertThat(key).isEmpty();
    }

    @Test
    void getKeyByKid_keyOpsWithVerify_returnsKey() throws Exception {
        JwksCache cache =
                cacheWith(
                        Map.of(
                                "keys",
                                List.of(
                                        Map.of(
                                                "kty", "RSA",
                                                "kid", "k1",
                                                "key_ops", List.of("verify")))));

        Optional<Map<String, Object>> key = cache.getKeyByKid("k1", false);

        assertThat(key).isPresent();
    }

    @Test
    void getKeyByKid_keyEntryNotAMap_skippedQuietly() throws Exception {
        JwksCache cache =
                cacheWith(
                        Map.of(
                                "keys",
                                List.of(
                                        "not-a-key",
                                        Map.of("kty", "RSA", "kid", "k1", "use", "sig"))));

        Optional<Map<String, Object>> key = cache.getKeyByKid("k1", false);

        assertThat(key).isPresent();
    }

    @Test
    void getKeyByKid_withForceRefresh_fetchesAndFinds() throws Exception {
        JwksCache cache =
                cacheWith(Map.of("keys", List.of(Map.of("kty", "RSA", "kid", "k1", "use", "sig"))));

        Optional<Map<String, Object>> key = cache.getKeyByKid("k1", true);

        assertThat(key).isPresent();
    }
}
