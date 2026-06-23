package ai.authplane.sdk.core.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.concurrent.ThreadLocalRandom;

import org.junit.jupiter.api.Test;

class InMemoryDPoPReplayStoreTest {

    @Test
    void constructor_negativeOrZero_throws() {
        assertThatThrownBy(() -> new InMemoryDPoPReplayStore(0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxEntries");
        assertThatThrownBy(() -> new InMemoryDPoPReplayStore(-1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void storeIfAbsent_firstSeenJti_returnsTrue() {
        InMemoryDPoPReplayStore store = new InMemoryDPoPReplayStore();

        boolean stored = store.storeIfAbsent("jti-1", Instant.now().plusSeconds(60));

        assertThat(stored).isTrue();
    }

    @Test
    void storeIfAbsent_replay_returnsFalse() {
        InMemoryDPoPReplayStore store = new InMemoryDPoPReplayStore();
        Instant expiry = Instant.now().plusSeconds(60);

        store.storeIfAbsent("jti-replay", expiry);
        boolean second = store.storeIfAbsent("jti-replay", expiry);

        assertThat(second).isFalse();
    }

    @Test
    void storeIfAbsent_nullJti_throws() {
        InMemoryDPoPReplayStore store = new InMemoryDPoPReplayStore();
        assertThatThrownBy(() -> store.storeIfAbsent(null, Instant.now().plusSeconds(60)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("jti");
    }

    @Test
    void storeIfAbsent_blankJti_throws() {
        InMemoryDPoPReplayStore store = new InMemoryDPoPReplayStore();
        assertThatThrownBy(() -> store.storeIfAbsent("   ", Instant.now().plusSeconds(60)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void storeIfAbsent_nullExpiry_throws() {
        InMemoryDPoPReplayStore store = new InMemoryDPoPReplayStore();
        assertThatThrownBy(() -> store.storeIfAbsent("jti", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expiresAt");
    }

    @Test
    void storeIfAbsent_expiredEntry_isEvictedAndAllowsReReplay() {
        InMemoryDPoPReplayStore store = new InMemoryDPoPReplayStore();
        // Store an entry that's already expired
        Instant past = Instant.now().minusSeconds(60);

        store.storeIfAbsent("jti-old", past);
        // Storing again with a future expiry should succeed: the old entry is evicted
        boolean stored = store.storeIfAbsent("jti-old", Instant.now().plusSeconds(60));

        assertThat(stored).isTrue();
    }

    @Test
    void storeIfAbsent_atCapacity_throwsIllegalState() {
        InMemoryDPoPReplayStore store = new InMemoryDPoPReplayStore(2);
        Instant future = Instant.now().plusSeconds(3600);

        store.storeIfAbsent("a", future);
        store.storeIfAbsent("b", future);

        assertThatThrownBy(() -> store.storeIfAbsent("c", future))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("capacity");
    }

    @Test
    void storeIfAbsent_capacityAfterEviction_succeeds() {
        InMemoryDPoPReplayStore store = new InMemoryDPoPReplayStore(2);
        Instant past = Instant.now().minusSeconds(60);
        Instant future = Instant.now().plusSeconds(60);

        store.storeIfAbsent("a", past);
        store.storeIfAbsent("b", past);
        // Both expired; eviction makes room for new entries
        boolean stored = store.storeIfAbsent("c-" + ThreadLocalRandom.current().nextLong(), future);

        assertThat(stored).isTrue();
    }
}
