package ai.authplane.sdk.core.errors;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import ai.authplane.sdk.core.dpop.DPoPNotSupportedException;
import ai.authplane.sdk.core.dpop.DPoPProofMissingException;
import ai.authplane.sdk.core.dpop.MultipleDpopProofsException;

/**
 * Tests for the exception hierarchy.
 *
 * <p>Each exception class only declares constructors; this file verifies that all constructors are
 * reachable, the message is preserved, and the cause chain is correct. This ensures full
 * instruction coverage for the errors package.
 */
class ErrorsTest {

    private static final String MSG = "test message";
    private static final RuntimeException CAUSE = new RuntimeException("root cause");

    // -----------------------------------------------------------------------
    // AuthplaneException (base)
    // -----------------------------------------------------------------------

    @Test
    void authplaneException_messageConstructor() {
        AuthplaneException ex = new AuthplaneException(MSG) {};
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex.getCause()).isNull();
        assertThat(ex).isInstanceOf(RuntimeException.class);
    }

    @Test
    void authplaneException_messageCauseConstructor() {
        AuthplaneException ex = new AuthplaneException(MSG, CAUSE) {};
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex.getCause()).isSameAs(CAUSE);
    }

    // -----------------------------------------------------------------------
    // InvalidClaimsException
    // -----------------------------------------------------------------------

    @Test
    void invalidClaimsException_messageConstructor() {
        InvalidClaimsException ex = new InvalidClaimsException(MSG);
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex).isInstanceOf(AuthplaneException.class);
    }

    @Test
    void invalidClaimsException_messageCauseConstructor() {
        InvalidClaimsException ex = new InvalidClaimsException(MSG, CAUSE);
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex.getCause()).isSameAs(CAUSE);
    }

    // -----------------------------------------------------------------------
    // InvalidSignatureException
    // -----------------------------------------------------------------------

    @Test
    void invalidSignatureException_messageConstructor() {
        InvalidSignatureException ex = new InvalidSignatureException(MSG);
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex).isInstanceOf(AuthplaneException.class);
    }

    @Test
    void invalidSignatureException_messageCauseConstructor() {
        InvalidSignatureException ex = new InvalidSignatureException(MSG, CAUSE);
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex.getCause()).isSameAs(CAUSE);
    }

    // -----------------------------------------------------------------------
    // TokenExpiredException
    // -----------------------------------------------------------------------

    @Test
    void tokenExpiredException_messageConstructor() {
        TokenExpiredException ex = new TokenExpiredException(MSG);
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex).isInstanceOf(AuthplaneException.class);
    }

    @Test
    void tokenExpiredException_messageCauseConstructor() {
        TokenExpiredException ex = new TokenExpiredException(MSG, CAUSE);
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex.getCause()).isSameAs(CAUSE);
    }

    // -----------------------------------------------------------------------
    // JwksFetchException
    // -----------------------------------------------------------------------

    @Test
    void jwksFetchException_messageConstructor() {
        JwksFetchException ex = new JwksFetchException(MSG);
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex).isInstanceOf(AuthplaneException.class);
    }

    @Test
    void jwksFetchException_messageCauseConstructor() {
        JwksFetchException ex = new JwksFetchException(MSG, CAUSE);
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex.getCause()).isSameAs(CAUSE);
    }

    // -----------------------------------------------------------------------
    // MetadataFetchException
    // -----------------------------------------------------------------------

    @Test
    void metadataFetchException_messageConstructor() {
        MetadataFetchException ex = new MetadataFetchException(MSG);
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex).isInstanceOf(AuthplaneException.class);
    }

    @Test
    void metadataFetchException_messageCauseConstructor() {
        MetadataFetchException ex = new MetadataFetchException(MSG, CAUSE);
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex.getCause()).isSameAs(CAUSE);
    }

    // -----------------------------------------------------------------------
    // TokenMissingException
    // -----------------------------------------------------------------------

    @Test
    void tokenMissingException_messageConstructor() {
        TokenMissingException ex = new TokenMissingException(MSG);
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex).isInstanceOf(AuthplaneException.class);
    }

    // -----------------------------------------------------------------------
    // InsufficientScopeException
    // -----------------------------------------------------------------------

    @Test
    void insufficientScopeException_containsScopeInfo() {
        InsufficientScopeException ex =
                new InsufficientScopeException("write:data", List.of("read:data"));
        assertThat(ex.getMessage()).contains("write:data");
        assertThat(ex).isInstanceOf(AuthplaneException.class);
        assertThat(ex.getRequiredScope()).isEqualTo("write:data");
        assertThat(ex.getRequiredScopes()).containsExactly("write:data");
        assertThat(ex.getAvailableScopes()).containsExactly("read:data");
    }

    @Test
    void insufficientScopeException_emptyTokenRendersNoneNotBrackets() {
        InsufficientScopeException ex = new InsufficientScopeException("write:data", List.of());
        assertThat(ex.getMessage()).contains("token has (none)");
        assertThat(ex.getMessage()).doesNotContain("[]");
    }

    @Test
    void insufficientScopeException_pluralNamesEveryMissingScope() {
        InsufficientScopeException ex =
                new InsufficientScopeException(
                        List.of("read:data", "write:data", "admin:all"), List.of("read:data"));
        // Names both missing scopes, not just the first.
        assertThat(ex.getMessage()).contains("write:data").contains("admin:all");
        assertThat(ex.getRequiredScopes()).containsExactly("read:data", "write:data", "admin:all");
        assertThat(ex.getRequiredScope()).isEqualTo("read:data");
        assertThat(ex.getAvailableScopes()).containsExactly("read:data");
    }

    // -----------------------------------------------------------------------
    // Exception hierarchy
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // TokenRevokedException
    // -----------------------------------------------------------------------

    @Test
    void tokenRevokedException_messageConstructor() {
        TokenRevokedException ex = new TokenRevokedException(MSG);
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex).isInstanceOf(AuthplaneException.class);
    }

    // -----------------------------------------------------------------------
    // Exception hierarchy
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // WwwAuthenticate — quoted-string escaping
    // -----------------------------------------------------------------------

    @Test
    void wwwAuthenticate_escapesDoubleQuotesInErrorDescription() {
        var ex = new InvalidClaimsException("bad \"kid\" value");
        String header = WwwAuthenticate.of(ex);
        assertThat(header).contains("error_description=\"bad \\\"kid\\\" value\"");
    }

    @Test
    void wwwAuthenticate_escapesBackslashesInErrorDescription() {
        var ex = new InvalidClaimsException("path\\to\\file");
        String header = WwwAuthenticate.of(ex);
        assertThat(header).contains("error_description=\"path\\\\to\\\\file\"");
    }

    @Test
    void wwwAuthenticate_escapesQuotedStringHelper() {
        assertThat(WwwAuthenticate.escapeQuotedString("no specials")).isEqualTo("no specials");
        assertThat(WwwAuthenticate.escapeQuotedString("a\"b")).isEqualTo("a\\\"b");
        assertThat(WwwAuthenticate.escapeQuotedString("a\\b")).isEqualTo("a\\\\b");
        assertThat(WwwAuthenticate.escapeQuotedString("a\\\"b")).isEqualTo("a\\\\\\\"b");
        assertThat(WwwAuthenticate.escapeQuotedString(null)).isEqualTo("");
    }

    @Test
    void wwwAuthenticate_stripsAllControlCharsNotJustCrLf() {
        // Tab (0x09) and DEL (0x7f) are control chars illegal in a header field-value;
        // escapeQuotedString strips the whole C0 range + DEL, not only CR/LF. A space (0x20) is
        // not a control char and is preserved.
        String input = "x" + (char) 0x09 + "y" + (char) 0x7f + "z w";
        assertThat(WwwAuthenticate.escapeQuotedString(input)).isEqualTo("xyz w");
    }

    @Test
    void wwwAuthenticate_stripsCrLfFromErrorDescription() {
        // CR/LF cannot appear inside a quoted-string (RFC 9110 §5.6.4); leaving them in would
        // let an attacker inject a follow-on header line.
        var ex = new InvalidClaimsException("line1\r\nSet-Cookie: pwned=1");
        String header = WwwAuthenticate.of(ex);
        assertThat(header).doesNotContain("\r");
        assertThat(header).doesNotContain("\n");
        assertThat(header).contains("error_description=\"line1Set-Cookie: pwned=1\"");
    }

    @Test
    void wwwAuthenticate_escapesRealm() {
        // Realm runs through the same sanitisation as error_description so an operator-controlled
        // value cannot break out of the quoted-string.
        var ex = new TokenExpiredException("expired");
        String header = WwwAuthenticate.of(ex, "realm-with-\"-and-\\-and-\r\n-inside");
        assertThat(header).contains("realm=\"realm-with-\\\"-and-\\\\-and--inside\"");
        assertThat(header).doesNotContain("\r");
        assertThat(header).doesNotContain("\n");
    }

    @Test
    void wwwAuthenticate_challengeOptions_emitsResourceMetadataAndScope() {
        var ex = new InsufficientScopeException("admin", List.of("read"));
        String header =
                WwwAuthenticate.of(
                        ex,
                        WwwAuthenticate.ChallengeOptions.empty()
                                .withRealm("https://api.example.com")
                                .withResourceMetadataUrl(
                                        "https://api.example.com/.well-known/oauth-protected-resource")
                                .withScope(List.of("admin", "tools/write")));
        assertThat(header).startsWith("Bearer ");
        assertThat(header).contains("realm=\"https://api.example.com\"");
        assertThat(header).contains("error=\"insufficient_scope\"");
        assertThat(header).contains("scope=\"admin tools/write\"");
        assertThat(header)
                .contains(
                        "resource_metadata=\"https://api.example.com/.well-known/oauth-protected-resource\"");
    }

    @Test
    void wwwAuthenticate_challengeOptions_omitsEmptyParameters() {
        var ex = new TokenExpiredException("expired");
        String header =
                WwwAuthenticate.of(
                        ex,
                        WwwAuthenticate.ChallengeOptions.empty()
                                .withRealm("")
                                .withResourceMetadataUrl(""));
        assertThat(header).doesNotContain("realm=");
        assertThat(header).doesNotContain("scope=");
        assertThat(header).doesNotContain("resource_metadata=");
        assertThat(header).contains("error=\"invalid_token\"");
    }

    @Test
    void wwwAuthenticate_challengeOptions_escapesResourceMetadataAndScope() {
        var ex = new InsufficientScopeException("admin", List.of("read"));
        String header =
                WwwAuthenticate.of(
                        ex,
                        WwwAuthenticate.ChallengeOptions.empty()
                                .withResourceMetadataUrl(
                                        "https://api.example.com/prm\r\nX-Injected: 1")
                                .withScope(List.of("a\"b", "c\\d")));
        assertThat(header).doesNotContain("\r");
        assertThat(header).doesNotContain("\n");
        assertThat(header).contains("scope=\"a\\\"b c\\\\d\"");
        assertThat(header)
                .contains("resource_metadata=\"https://api.example.com/prmX-Injected: 1\"");
    }

    @Test
    void wwwAuthenticate_challengeOptions_nullArgs_throw() {
        assertThat(WwwAuthenticate.ChallengeOptions.empty().scope()).isEmpty();
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> WwwAuthenticate.of(null, WwwAuthenticate.ChallengeOptions.empty()))
                .isInstanceOf(NullPointerException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () ->
                                WwwAuthenticate.of(
                                        new TokenExpiredException("x"),
                                        (WwwAuthenticate.ChallengeOptions) null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void wwwAuthenticate_dpopException_usesDpopScheme() {
        String header = WwwAuthenticate.of(new DPoPProofMissingException(MSG));
        assertThat(header).startsWith("DPoP ");
        assertThat(header).contains("error=\"invalid_token\"");
    }

    @Test
    void wwwAuthenticate_dpopNotSupported_usesBearerScheme() {
        String header = WwwAuthenticate.of(new DPoPNotSupportedException(MSG));
        assertThat(header).startsWith("Bearer ");
        assertThat(header).contains("error=\"invalid_token\"");
    }

    @Test
    void wwwAuthenticate_multipleDpopProofs_usesDpopSchemeAndInvalidDpopProofCode() {
        String header = WwwAuthenticate.of(new MultipleDpopProofsException(MSG));
        assertThat(header).startsWith("DPoP ");
        assertThat(header).contains("error=\"invalid_dpop_proof\"");
    }

    @Test
    void multipleDpopProofsException_messageConstructor() {
        MultipleDpopProofsException ex = new MultipleDpopProofsException(MSG);
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex).isInstanceOf(AuthplaneException.class);
    }

    @Test
    void multipleDpopProofsException_messageCauseConstructor() {
        MultipleDpopProofsException ex = new MultipleDpopProofsException(MSG, CAUSE);
        assertThat(ex.getMessage()).isEqualTo(MSG);
        assertThat(ex.getCause()).isSameAs(CAUSE);
    }

    @Test
    void httpStatus_multipleDpopProofs_returns401() {
        assertThat(HttpStatus.of(new MultipleDpopProofsException(MSG))).isEqualTo(401);
    }

    @Test
    void httpStatus_dpopNotSupported_returns401() {
        assertThat(HttpStatus.of(new DPoPNotSupportedException(MSG))).isEqualTo(401);
    }

    @Test
    void allExceptions_extendAuthplaneException() {
        assertThat(new InvalidClaimsException(MSG)).isInstanceOf(AuthplaneException.class);
        assertThat(new InvalidSignatureException(MSG)).isInstanceOf(AuthplaneException.class);
        assertThat(new TokenExpiredException(MSG)).isInstanceOf(AuthplaneException.class);
        assertThat(new JwksFetchException(MSG)).isInstanceOf(AuthplaneException.class);
        assertThat(new MetadataFetchException(MSG)).isInstanceOf(AuthplaneException.class);
        assertThat(new TokenMissingException(MSG)).isInstanceOf(AuthplaneException.class);
        assertThat(new TokenRevokedException(MSG)).isInstanceOf(AuthplaneException.class);
    }

    @Test
    void authplaneException_extendsRuntimeException() {
        // Must be unchecked so callers don't need to declare it
        assertThat(new InvalidClaimsException(MSG)).isInstanceOf(RuntimeException.class);
    }

    // -----------------------------------------------------------------------
    // HttpStatus
    // -----------------------------------------------------------------------

    @Test
    void httpStatus_insufficientScope_returns403() {
        assertThat(HttpStatus.of(new InsufficientScopeException("read", List.of()))).isEqualTo(403);
    }

    @Test
    void httpStatus_jwksFetch_returns503() {
        assertThat(HttpStatus.of(new JwksFetchException(MSG))).isEqualTo(503);
    }

    @Test
    void httpStatus_metadataFetch_returns503() {
        assertThat(HttpStatus.of(new MetadataFetchException(MSG))).isEqualTo(503);
    }

    @Test
    void httpStatus_tokenExchange_returns500() {
        assertThat(HttpStatus.of(new TokenExchangeException(MSG, null))).isEqualTo(500);
    }

    @Test
    void httpStatus_tokenMissing_returns401() {
        assertThat(HttpStatus.of(new TokenMissingException(MSG))).isEqualTo(401);
    }

    @Test
    void httpStatus_tokenExpired_returns401() {
        assertThat(HttpStatus.of(new TokenExpiredException(MSG))).isEqualTo(401);
    }

    @Test
    void httpStatus_invalidSignature_returns401() {
        assertThat(HttpStatus.of(new InvalidSignatureException(MSG))).isEqualTo(401);
    }

    @Test
    void httpStatus_invalidClaims_returns401() {
        assertThat(HttpStatus.of(new InvalidClaimsException(MSG))).isEqualTo(401);
    }

    @Test
    void httpStatus_tokenRevoked_returns401() {
        assertThat(HttpStatus.of(new TokenRevokedException(MSG))).isEqualTo(401);
    }

    @Test
    void httpStatus_dpopException_returns401() {
        assertThat(HttpStatus.of(new DPoPProofMissingException(MSG))).isEqualTo(401);
    }

    @Test
    void httpStatus_unknownAuthplaneException_returns500() {
        AuthplaneException custom = new AuthplaneException(MSG) {};
        assertThat(HttpStatus.of(custom)).isEqualTo(500);
    }
}
