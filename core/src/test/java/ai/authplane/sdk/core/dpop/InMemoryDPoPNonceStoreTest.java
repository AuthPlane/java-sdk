package ai.authplane.sdk.core.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class InMemoryDPoPNonceStoreTest {

    @Test
    void get_returnsEmptyStringForUnknownOrigin() {
        InMemoryDPoPNonceStore store = new InMemoryDPoPNonceStore();
        assertThat(store.get("https://as.example.com")).isEmpty();
    }

    @Test
    void put_thenGet_returnsStoredNonce() {
        InMemoryDPoPNonceStore store = new InMemoryDPoPNonceStore();
        store.put("https://as.example.com", "abc123");
        assertThat(store.get("https://as.example.com")).isEqualTo("abc123");
    }

    @Test
    void put_overwritesExistingNonceForSameOrigin() {
        InMemoryDPoPNonceStore store = new InMemoryDPoPNonceStore();
        store.put("https://as.example.com", "first");
        store.put("https://as.example.com", "second");
        assertThat(store.get("https://as.example.com")).isEqualTo("second");
    }

    @Test
    void put_isolatesNoncesPerOrigin() {
        InMemoryDPoPNonceStore store = new InMemoryDPoPNonceStore();
        store.put("https://as1.example.com", "n1");
        store.put("https://as2.example.com", "n2");
        assertThat(store.get("https://as1.example.com")).isEqualTo("n1");
        assertThat(store.get("https://as2.example.com")).isEqualTo("n2");
    }

    @Test
    void put_ignoresBlankNonce() {
        InMemoryDPoPNonceStore store = new InMemoryDPoPNonceStore();
        store.put("https://as.example.com", "previous");
        store.put("https://as.example.com", "");
        store.put("https://as.example.com", "   ");
        store.put("https://as.example.com", null);
        assertThat(store.get("https://as.example.com")).isEqualTo("previous");
    }

    @Test
    void put_rejectsBlankOrigin() {
        InMemoryDPoPNonceStore store = new InMemoryDPoPNonceStore();
        assertThatThrownBy(() -> store.put("", "n"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("origin");
        assertThatThrownBy(() -> store.put("   ", "n"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> store.put(null, "n")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void put_evictsOldestEntryWhenAtCapacity() {
        InMemoryDPoPNonceStore store = new InMemoryDPoPNonceStore(2);
        store.put("origin-a", "n-a");
        store.put("origin-b", "n-b");
        store.put("origin-c", "n-c");
        // origin-a should be evicted (oldest insertion)
        assertThat(store.get("origin-a")).isEmpty();
        assertThat(store.get("origin-b")).isEqualTo("n-b");
        assertThat(store.get("origin-c")).isEqualTo("n-c");
    }

    @Test
    void constructor_rejectsZeroMaxEntries() {
        assertThatThrownBy(() -> new InMemoryDPoPNonceStore(0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxEntries must be positive");
    }

    @Test
    void constructor_rejectsNegativeMaxEntries() {
        assertThatThrownBy(() -> new InMemoryDPoPNonceStore(-5))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
