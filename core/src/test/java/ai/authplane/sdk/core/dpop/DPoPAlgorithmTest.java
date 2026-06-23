package ai.authplane.sdk.core.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;

class DPoPAlgorithmTest {

    @Test
    void value_returnsWireFormat() {
        assertThat(DPoPAlgorithm.RS256.value()).isEqualTo("RS256");
        assertThat(DPoPAlgorithm.ES256.value()).isEqualTo("ES256");
    }

    @Test
    void jwsAlgorithm_returnsNimbusEquivalent() {
        assertThat(DPoPAlgorithm.RS256.jwsAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(DPoPAlgorithm.ES256.jwsAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
    }

    @Test
    void fromValue_parsesSupportedNames() {
        assertThat(DPoPAlgorithm.fromValue("RS256")).isEqualTo(DPoPAlgorithm.RS256);
        assertThat(DPoPAlgorithm.fromValue("ES256")).isEqualTo(DPoPAlgorithm.ES256);
    }

    @Test
    void fromValue_rejectsUnsupportedAlgorithm() {
        assertThatThrownBy(() -> DPoPAlgorithm.fromValue("HS256"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported DPoP algorithm");
    }

    @Test
    void fromValue_rejectsUnknownString() {
        assertThatThrownBy(() -> DPoPAlgorithm.fromValue("not-a-real-alg"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void fromValue_isCaseSensitive() {
        assertThatThrownBy(() -> DPoPAlgorithm.fromValue("rs256"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
