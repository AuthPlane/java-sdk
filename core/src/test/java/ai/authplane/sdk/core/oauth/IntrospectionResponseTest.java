package ai.authplane.sdk.core.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

class IntrospectionResponseTest {

    @Test
    void nullRaw_becomesEmptyImmutableMap() {
        IntrospectionResponse resp = new IntrospectionResponse(false, null);
        assertThat(resp.raw()).isEmpty();
        assertThatThrownBy(() -> resp.raw().put("k", "v"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void cnf_returnsTopLevelConfirmationClaim() {
        IntrospectionResponse resp =
                new IntrospectionResponse(true, Map.of("cnf", Map.of("jkt", "thumb-abc")));
        assertThat(resp.cnf()).containsEntry("jkt", "thumb-abc");
    }

    @Test
    void cnf_absent_returnsEmptyMap() {
        IntrospectionResponse resp = new IntrospectionResponse(true, Map.of("sub", "user"));
        assertThat(resp.cnf()).isEmpty();
    }

    @Test
    void cnf_isImmutable() {
        IntrospectionResponse resp =
                new IntrospectionResponse(true, Map.of("cnf", Map.of("jkt", "thumb-abc")));
        assertThatThrownBy(() -> resp.cnf().put("x", "y"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void dpopThumbprint_returnsJktWhenPresent() {
        IntrospectionResponse resp =
                new IntrospectionResponse(true, Map.of("cnf", Map.of("jkt", "thumb-abc")));
        assertThat(resp.dpopThumbprint()).isEqualTo("thumb-abc");
    }

    @Test
    void dpopThumbprint_nullWhenCnfAbsent() {
        IntrospectionResponse resp = new IntrospectionResponse(true, Map.of("sub", "user"));
        assertThat(resp.dpopThumbprint()).isNull();
    }

    @Test
    void dpopThumbprint_nullWhenJktBlank() {
        IntrospectionResponse resp =
                new IntrospectionResponse(true, Map.of("cnf", Map.of("jkt", "")));
        assertThat(resp.dpopThumbprint()).isNull();
    }

    @Test
    void dpopThumbprint_nullWhenJktNotString() {
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jkt", 42);
        IntrospectionResponse resp = new IntrospectionResponse(true, Map.of("cnf", cnf));
        assertThat(resp.dpopThumbprint()).isNull();
    }
}
