package ai.authplane.sdk.core.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

class DPoPKeyMaterialTest {

    private static RSAKey rsaPrivate;
    private static ECKey ecP256Private;
    private static ECKey ecP384Private;

    @BeforeAll
    static void generateKeys() throws Exception {
        rsaPrivate = new RSAKeyGenerator(2048).generate();
        ecP256Private = new ECKeyGenerator(Curve.P_256).generate();
        ecP384Private = new ECKeyGenerator(Curve.P_384).generate();
    }

    @Test
    void fromJwk_buildsRs256Material() {
        DPoPKeyMaterial mat = DPoPKeyMaterial.fromJwk(rsaPrivate, DPoPAlgorithm.RS256);
        assertThat(mat.algorithm()).isEqualTo(DPoPAlgorithm.RS256);
        assertThat(mat.publicJwk().isPrivate()).isFalse();
        assertThat(mat.thumbprint()).isNotBlank();
    }

    @Test
    void fromJwk_buildsEs256Material() {
        DPoPKeyMaterial mat = DPoPKeyMaterial.fromJwk(ecP256Private, DPoPAlgorithm.ES256);
        assertThat(mat.algorithm()).isEqualTo(DPoPAlgorithm.ES256);
        assertThat(mat.publicJwk().isPrivate()).isFalse();
        assertThat(mat.thumbprint()).isNotBlank();
    }

    @Test
    void fromJwk_thumbprintIsRfc7638() {
        DPoPKeyMaterial mat = DPoPKeyMaterial.fromJwk(rsaPrivate, DPoPAlgorithm.RS256);
        // RFC 7638 thumbprints are base64url-encoded SHA-256 (43 chars).
        assertThat(mat.thumbprint()).hasSize(43);
    }

    @Test
    void fromJwk_rejectsNullKey() {
        assertThatThrownBy(() -> DPoPKeyMaterial.fromJwk(null, DPoPAlgorithm.RS256))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("privateJwk");
    }

    @Test
    void fromJwk_rejectsNullAlgorithm() {
        assertThatThrownBy(() -> DPoPKeyMaterial.fromJwk(rsaPrivate, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("algorithm");
    }

    @Test
    void fromJwk_rejectsPublicOnlyJwk() {
        JWK publicOnly = rsaPrivate.toPublicJWK();
        assertThatThrownBy(() -> DPoPKeyMaterial.fromJwk(publicOnly, DPoPAlgorithm.RS256))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("private JWK");
    }

    @Test
    void fromJwk_rejectsRsaKeyForEs256() {
        assertThatThrownBy(() -> DPoPKeyMaterial.fromJwk(rsaPrivate, DPoPAlgorithm.ES256))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ES256 DPoP keys must be P-256 EC keys");
    }

    @Test
    void fromJwk_rejectsEcKeyForRs256() {
        assertThatThrownBy(() -> DPoPKeyMaterial.fromJwk(ecP256Private, DPoPAlgorithm.RS256))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("RS256 DPoP keys must be RSA");
    }

    @Test
    void fromJwk_rejectsNonP256CurveForEs256() {
        assertThatThrownBy(() -> DPoPKeyMaterial.fromJwk(ecP384Private, DPoPAlgorithm.ES256))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("P-256");
    }

    // fromPem coverage is exercised in integration scenarios where BouncyCastle
    // is on the classpath; Nimbus JOSE delegates PEM parsing to BC via its
    // JcaPEMKeyConverter, which the SDK does not pull in as a hard dependency.
    // Leaving the path uncovered in unit tests is acceptable.

    @Test
    void fromPublicAndPrivateJwks_buildsMaterial() {
        Map<String, Object> priv = rsaPrivate.toJSONObject();
        Map<String, Object> pub = rsaPrivate.toPublicJWK().toJSONObject();
        DPoPKeyMaterial mat =
                DPoPKeyMaterial.fromPublicAndPrivateJwks(priv, pub, DPoPAlgorithm.RS256);
        assertThat(mat.algorithm()).isEqualTo(DPoPAlgorithm.RS256);
        assertThat(mat.thumbprint()).isNotBlank();
    }

    @Test
    void fromPublicAndPrivateJwks_rejectsAlgorithmMismatch() {
        Map<String, Object> priv = rsaPrivate.toJSONObject();
        Map<String, Object> pub = rsaPrivate.toPublicJWK().toJSONObject();
        assertThatThrownBy(
                        () ->
                                DPoPKeyMaterial.fromPublicAndPrivateJwks(
                                        priv, pub, DPoPAlgorithm.ES256))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void fromPublicAndPrivateJwks_rejectsMalformedMap() {
        assertThatThrownBy(
                        () ->
                                DPoPKeyMaterial.fromPublicAndPrivateJwks(
                                        Map.of("kty", "oops"),
                                        Map.of("kty", "oops"),
                                        DPoPAlgorithm.RS256))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void publicJwk_strippedOfPrivateMaterial() {
        DPoPKeyMaterial mat = DPoPKeyMaterial.fromJwk(rsaPrivate, DPoPAlgorithm.RS256);
        assertThat(mat.publicJwk().isPrivate()).isFalse();
    }
}
