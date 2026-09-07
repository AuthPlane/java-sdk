package ai.authplane.sdk.core.prm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.LIST;

import java.net.URI;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ProtectedResourceMetadataTest {

    @Test
    void wellKnownPath_rootResource() {
        assertThat(ProtectedResourceMetadata.wellKnownPath(URI.create("https://api.example.com")))
                .isEqualTo("/.well-known/oauth-protected-resource");
    }

    @Test
    void wellKnownPath_resourceWithPath() {
        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/mcp")))
                .isEqualTo("/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void wellKnownPath_resourceWithTrailingSlash_stripped() {
        // The terminating slash is stripped only when deriving the well-known path (RFC 9728
        // §3.1); the resource identifier itself is compared verbatim. "/mcp/" →
        // ".../oauth-protected-resource/mcp".
        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/mcp/")))
                .isEqualTo("/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void wellKnownPath_rootResourceWithTrailingSlash() {
        // A root resource carrying only a terminating slash (path "/") derives the bare
        // well-known path — exercises the path.equals("/") branch (RFC 9728 §3.1).
        assertThat(ProtectedResourceMetadata.wellKnownPath(URI.create("https://api.example.com/")))
                .isEqualTo("/.well-known/oauth-protected-resource");
    }

    @Test
    void builder_rejectsFragmentInResource() {
        // RFC 8707 §2: "The URI MUST NOT include a fragment component." The builder stores the
        // identifier verbatim into the document's "resource" field while the well-known URL is
        // derived from a java.net.URI that has already dropped the fragment — the two would name
        // different identifiers, and RFC 9728 §3.3 makes a conformant client discard such a
        // document. There is no server-side error in that failure, so it must be rejected here.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.builder()
                                        .resource("https://api.example.com/mcp#section")
                                        .authorizationServer("https://auth.example.com")
                                        .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a fragment component")
                .hasMessageContaining("https://api.example.com/mcp");
    }

    @Test
    void builder_rejectsEmptyFragmentInResource() {
        // A bare trailing "#" is still a fragment component, and it is dropped just as silently.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.builder()
                                        .resource("https://api.example.com/mcp#")
                                        .authorizationServer("https://auth.example.com")
                                        .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a fragment component");
    }

    @Test
    void builder_acceptsPercentEncodedHash() {
        // "%23" is a literal '#' in the path, not a fragment delimiter (RFC 3986 §3.5). The gate
        // scans for the raw character precisely so an encoded octet is not mistaken for one.
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://api.example.com/a%23b")
                        .authorizationServer("https://auth.example.com")
                        .build();
        assertThat(prm.getResource()).isEqualTo("https://api.example.com/a%23b");
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/a%23b"))
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource/a%23b");
    }

    @Test
    void derivationHelpers_rejectFragmentAsBackstop() {
        // Both helpers are public and are called on the 401 challenge path (prmUrl() feeds the
        // resource_metadata parameter), so they refuse to derive from a fragment-bearing
        // identifier rather than silently deriving from its fragment-free prefix.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.wellKnownPath(
                                        URI.create("https://api.example.com/mcp#section")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a fragment component");

        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.wellKnownUrl(
                                        "https://api.example.com/mcp#section"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a fragment component");
    }

    @Test
    void derivationHelpers_reportTheFragmentBeforeNonDerivability() {
        // Both checks can fail on the same identifier. A fragment is unconditionally illegal
        // (RFC 8707 §2); non-derivability is a limitation of these helpers. Reporting the fragment
        // first is both the more accurate diagnosis and what keeps the fragment out of the message
        // — requireDerivable interpolates the identifier whole.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.wellKnownUrl(
                                        "urn:example:api#s3cr3t-fragment"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a fragment component")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cr3t-fragment"));

        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.wellKnownPath(
                                        URI.create("/mcp#s3cr3t-fragment")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a fragment component")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cr3t-fragment"));
    }

    @Test
    void errorMessages_elideUserinfoAsWellAsTheFragment() {
        // The elision stopped at the fragment, but the userinfo is in the prefix that gets echoed
        // — and it is the component most likely to carry a credential.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.requireNoFragment(
                                        "https://user:s3cr3t@api.example.com/mcp#x"))
                .isInstanceOf(IllegalArgumentException.class)
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cr3t"))
                .hasMessageContaining("https://***@api.example.com/mcp");

        // Same for the derivation guard, which interpolates an identifier it could not parse into
        // something derivable.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.wellKnownUrl(
                                        "https://user:s3cr3t@api.example.com"
                                                + "/mcp?x=1#invalid^authority"))
                .isInstanceOf(IllegalArgumentException.class)
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cr3t"));
    }

    @Test
    void requireValidQuery_rejectsOctetsOutsideTheRfc3986Grammar() {
        // A raw non-ASCII octet ships straight through escapeQuotedString (which strips only
        // control characters, '\' and '"') into a WWW-Authenticate field value that RFC 9110 §5.5
        // confines to US-ASCII.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.requireValidQuery(
                                        "https://api.example.com/mcp?q=ñ"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("RFC 3986 §3.4")
                .hasMessageContaining("U+00F1");

        // '[' and ']' are the ASCII residue: java.net.URI accepts them, §3.4 does not.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.requireValidQuery(
                                        "https://api.example.com/mcp?a=b[c]"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid character '['");

        // A malformed escape is not a valid pct-encoded triplet.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.requireValidQuery(
                                        "https://api.example.com/mcp?a=%zz"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("malformed percent-escape");

        // What java.net.URI rejects, but only when something finally parses the identifier — on
        // the 401 response path, as a 500. The gate moves that to construction.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.requireValidQuery(
                                        "https://api.example.com/mcp?a=b c"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid character ' '");
    }

    @Test
    void requireValidQuery_acceptsTheFullQueryProduction() {
        // query = *( pchar / "/" / "?" ), pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
        ProtectedResourceMetadata.requireValidQuery("https://api.example.com/mcp");
        ProtectedResourceMetadata.requireValidQuery("https://api.example.com/mcp?");
        ProtectedResourceMetadata.requireValidQuery("https://api.example.com/mcp?tenant=a");
        ProtectedResourceMetadata.requireValidQuery("https://api.example.com/mcp?a%23b=c");
        ProtectedResourceMetadata.requireValidQuery(
                "https://api.example.com/mcp?a=-._~!$&'()*+,;=:@/?");
        // The '?' inside a fragment is not a query; requireNoFragment owns that rejection.
        ProtectedResourceMetadata.requireValidQuery("https://api.example.com/mcp#frag?a=b c");
    }

    @Test
    void requireValidQuery_errorMessage_elidesTheQueryAndUserinfo() {
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.requireValidQuery(
                                        "https://user:s3cr3t@api.example.com/mcp?token=t0ps3cr3t["))
                .isInstanceOf(IllegalArgumentException.class)
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cr3t"))
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("t0ps3cr3t"))
                .hasMessageContaining("https://***@api.example.com/mcp");
    }

    @Test
    void requireValidQuery_null_throwsNamedNpe() {
        assertThatThrownBy(() -> ProtectedResourceMetadata.requireValidQuery(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("resourceUri must not be null");
    }

    @Test
    void derivationHelpers_rejectAnInvalidQueryAsBackstop() {
        // Both sit on the 401 challenge path, where an unparseable resource_metadata value would
        // surface as a 500 rather than as the challenge the client is waiting for.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.wellKnownUrl(
                                        "https://api.example.com/mcp?a=b[c]"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("RFC 3986 §3.4");

        // A URI java.net.URI itself accepts, so the backstop is the only thing standing between
        // the identifier and the challenge.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.wellKnownPath(
                                        URI.create("https://api.example.com/mcp?q=ñ")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("RFC 3986 §3.4");
    }

    @Test
    void builder_rejectsAnInvalidQuery() {
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.builder()
                                        .resource("https://api.example.com/mcp?q=ñ")
                                        .authorizationServer("https://auth.example.com")
                                        .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("RFC 3986 §3.4");
    }

    @Test
    void requireNoFragment_null_throwsNamedNpe() {
        // Public API: AuthplaneClient.resource(...) two frames up reports the same condition with
        // a message, so this must not surface as a bare NPE out of String.indexOf.
        assertThatThrownBy(() -> ProtectedResourceMetadata.requireNoFragment(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("resourceUri must not be null");
    }

    @Test
    void requireNoFragment_acceptsAFragmentFreeIdentifier() {
        // Query components, trailing slashes and opaque identifiers are a separate axis: the gate
        // is about the fragment and nothing else.
        ProtectedResourceMetadata.requireNoFragment("https://api.example.com/mcp");
        ProtectedResourceMetadata.requireNoFragment("https://api.example.com/mcp/?tenant=acme");
        ProtectedResourceMetadata.requireNoFragment("urn:example:api");
    }

    @Test
    void urnStyleResource_isAccepted() {
        // RFC 8707 §2 permits non-http(s) resource indicators. A urn: identifier must not be
        // rejected by any http(s)+authority validator — it is stored verbatim.
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("urn:example:api")
                        .authorizationServer("https://auth.example.com")
                        .build();
        assertThat(prm.getResource()).isEqualTo("urn:example:api");
        assertThat(prm.toMap().get("resource")).isEqualTo("urn:example:api");
    }

    @Test
    void urnStyleResource_cannotDeriveAPrmUrl() {
        // The identifier is stored verbatim (above), but there is no PRM URL to derive from an
        // opaque URI: it has no authority and no hierarchical path. Deriving anyway produced
        // "urn://null/.well-known/oauth-protected-resource", which AuthplaneResource.prmUrl()
        // hands straight to the resource_metadata parameter of the 401 challenge.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.wellKnownPath(
                                        URI.create("urn:example:api")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("hierarchical resource identifier");

        assertThatThrownBy(() -> ProtectedResourceMetadata.wellKnownUrl("urn:example:api"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("hierarchical resource identifier");
    }

    @Test
    void schemeRelativeResource_cannotDeriveAPrmUrl() {
        // A scheme-relative reference is neither opaque nor authority-less, so it cleared a gate
        // that tested only those two. The derivation then read a null scheme and emitted
        // "null://api.example.com/.well-known/oauth-protected-resource/mcp", which
        // AuthplaneResource.prmUrl() hands straight to the resource_metadata parameter of the
        // 401 challenge — a URL no client can resolve.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.wellKnownPath(
                                        URI.create("//api.example.com/mcp")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("a scheme and an authority");

        // wellKnownUrl now reports the missing scheme by name: requireScheme runs as one of its
        // four backstops and answers before requireDerivable is reached from wellKnownPath. Both
        // reject; this one says which component is missing.
        assertThatThrownBy(() -> ProtectedResourceMetadata.wellKnownUrl("//api.example.com/mcp"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("has no scheme");
    }

    @Test
    void requireScheme_rejectsSchemelessIdentifiers() {
        // The construction gate, not the derivation backstop: a scheme-less identifier is
        // unconditionally illegal (RFC 8707 §2 requires an absolute URI; RFC 3986 §4.3 says one
        // always begins with a scheme), and the derivation is not its only sink — the scheme is
        // also spliced into the DPoP htu binding target.
        for (String identifier :
                new String[] {
                    "//api.example.com/mcp", // scheme-relative
                    "/mcp", // path-relative
                    "api.example.com/mcp", // host without a scheme
                    "1https://api.example.com/mcp", // scheme must start with ALPHA (§3.1)
                    "?tenant=acme", // query-only reference
                }) {
            assertThatThrownBy(() -> ProtectedResourceMetadata.requireScheme(identifier))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("has no scheme");
        }
    }

    @Test
    void requireScheme_acceptsAnyAbsoluteUri() {
        // Scheme only — not scheme+host. An opaque absolute URI constructs (stored verbatim);
        // whether it can derive a PRM URL is the derivation gate's question.
        ProtectedResourceMetadata.requireScheme("https://api.example.com/mcp");
        ProtectedResourceMetadata.requireScheme("urn:example:api");
        ProtectedResourceMetadata.requireScheme("custom+v1.2-x://host/path");
    }

    @Test
    void requireScheme_errorMessage_elidesUserinfoInASchemeRelativeIdentifier() {
        // The rejected shape is exactly the one the redactor used to miss: no "://" anchor, so
        // the early return shipped the credential verbatim in a message asserting it was elided.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.requireScheme(
                                        "//svc:s3cr3t@api.example.com/mcp"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("***@api.example.com/mcp")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cr3t"));
    }

    @Test
    void requireScheme_null_throwsNamedNpe() {
        assertThatThrownBy(() -> ProtectedResourceMetadata.requireScheme(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("resourceUri");
    }

    @Test
    void builder_rejectsASchemeRelativeResource() {
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.builder()
                                        .resource("//api.example.com/mcp")
                                        .authorizationServer("https://auth.example.com")
                                        .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("has no scheme");
    }

    @Test
    void builder_reportsTheFragmentBeforeTheMissingScheme() {
        // The gate order holds for the new axis too: an identifier that is both scheme-less and
        // fragment-bearing is reported for the fragment, which also keeps the fragment out of
        // the message.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.builder()
                                        .resource("//api.example.com/mcp#secret")
                                        .authorizationServer("https://auth.example.com")
                                        .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a fragment component")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("secret"));
    }

    @Test
    void requireNoUserinfo_rejectsUserinfoBearingIdentifiers() {
        // RFC 9110 §4.2.4: userinfo is deprecated and a recipient is to reject a URI carrying
        // it. The identifier is published verbatim to unauthenticated callers, so the credential
        // must not survive construction — redacting it at the sinks only covers the sinks that
        // remember to redact.
        for (String identifier :
                new String[] {
                    "https://svc:s3cr3t@api.example.com/mcp",
                    "https://svc@api.example.com/mcp", // user, no password
                    "https://@api.example.com/mcp", // empty userinfo is still userinfo
                    "https://svc:s3cr3t@api.example.com:8443/mcp", // alongside a port
                    "https://svc:s3cr3t@api.example.com", // authority is the whole remainder
                    "https://svc:s3cr3t@api.example.com?tenant=acme", // authority ends at '?'
                }) {
            assertThatThrownBy(() -> ProtectedResourceMetadata.requireNoUserinfo(identifier))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must not include a userinfo component")
                    .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cr3t"));
        }
    }

    @Test
    void requireNoUserinfo_acceptsIdentifiersWithoutUserinfo() {
        // A ':' in the authority is a port delimiter far more often than a userinfo one, and an
        // IPv6 literal is nothing but colons — none of that is userinfo, and turning any of it
        // away would break ordinary configurations.
        ProtectedResourceMetadata.requireNoUserinfo("https://api.example.com/mcp");
        ProtectedResourceMetadata.requireNoUserinfo("https://api.example.com:8443/mcp");
        ProtectedResourceMetadata.requireNoUserinfo("http://localhost:8080/mcp");
        ProtectedResourceMetadata.requireNoUserinfo("https://[::1]:8443/mcp");
        ProtectedResourceMetadata.requireNoUserinfo("https://api.example.com/mcp?tenant=acme");
        // '@' is a pchar, so it is legal in a path and in a query and is not a userinfo
        // delimiter there (RFC 3986 §§3.3, 3.4).
        ProtectedResourceMetadata.requireNoUserinfo("https://api.example.com/mcp/a@b");
        ProtectedResourceMetadata.requireNoUserinfo("https://api.example.com/mcp?to=a@b");
        // No authority at all, so nothing can delimit userinfo — an opaque identifier still
        // constructs (RFC 8707 §2 permits any absolute URI).
        ProtectedResourceMetadata.requireNoUserinfo("urn:example:api");
        ProtectedResourceMetadata.requireNoUserinfo("mailto:ops@example.com");
        // The '@' lives in the fragment, which is not part of the authority. requireNoFragment
        // owns that rejection; this gate must not claim it.
        ProtectedResourceMetadata.requireNoUserinfo("https://api.example.com/mcp#a@b");
    }

    @Test
    void requireNoUserinfo_isNotFooledByASchemeRelativeIdentifierWithALaterSchemeSeparator() {
        // The redactor's anchoring defect in gate form: with "://" tested first the authority
        // would be anchored inside the query, leaving the real userinfo before it and the
        // identifier looking clean.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.requireNoUserinfo(
                                        "//svc:s3cr3t@api.example.com/mcp?next=https://x"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a userinfo component");
    }

    @Test
    void requireNoUserinfo_doesNotConjureAnAuthorityOutOfAQuery() {
        // "https:example.com/mcp" has a scheme but no authority; the "://" in its query is not
        // an authority delimiter, so the '@' that follows is a query octet, not userinfo.
        ProtectedResourceMetadata.requireNoUserinfo("https:example.com/mcp?u=http://a:b@c");
    }

    @Test
    void requireNoUserinfo_null_throwsNamedNpe() {
        assertThatThrownBy(() -> ProtectedResourceMetadata.requireNoUserinfo(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("resourceUri");
    }

    @Test
    void builder_rejectsUserinfoInResource() {
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.builder()
                                        .resource("https://svc:s3cr3t@api.example.com/mcp")
                                        .authorizationServer("https://auth.example.com")
                                        .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a userinfo component")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cr3t"));
    }

    @Test
    void builder_reportsTheMissingSchemeBeforeTheUserinfo() {
        // The userinfo gate runs last of the four, so a scheme-relative identifier that also
        // carries userinfo is reported for the scheme — the defect an operator fixes first — and
        // the credential is elided from that message either way.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.builder()
                                        .resource("//svc:s3cr3t@api.example.com/mcp")
                                        .authorizationServer("https://auth.example.com")
                                        .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("has no scheme")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cr3t"));
    }

    @Test
    void elideSecrets_elidesUserinfoWhenASchemeSeparatorFollowsInTheQuery() {
        // The residue this closes: "://" was matched before the leading "//", anchoring the
        // authority inside the query, so userInfoEnd < authorityStart returned early and the
        // message claiming the userinfo was elided carried it verbatim. Exercised through
        // requireScheme, which is the gate that rejects this shape and the one that renders it.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.requireScheme(
                                        "//svc:s3cr3t@api.example.com/mcp?next=https://x"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("***@api.example.com/mcp?next=https://x")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cr3t"));
    }

    @Test
    void elideSecrets_elidesUserinfoWhenTheSchemeIsInvalid() {
        // The redactor must not fail open. `authorityBounds` is strict on purpose — the gate must
        // not over-reject — but the redactor giving up and returning its input means an
        // identifier whose scheme does not parse ships its credential verbatim in a message that
        // ends "(fragment and any userinfo elided)". Over-redacting costs nothing here.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.requireScheme(
                                        "1https://svc:s3cr3t@api.example.com/mcp"))
                .isInstanceOf(IllegalArgumentException.class)
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cr3t"));
    }

    @Test
    void elideSecrets_elidesUserinfoWhenTheIdentifierHasLeadingWhitespace() {
        // The likelier spelling of the same fault: a config value out of YAML or env with a
        // leading space. Nothing on the construction path trims it, so it reaches the scheme gate
        // untouched and `schemeEnd` refuses it at index 0.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.requireScheme(
                                        " https://svc:s3cr3t@api.example.com/mcp"))
                .isInstanceOf(IllegalArgumentException.class)
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cr3t"));
    }

    @Test
    void wellKnownPath_stripsEveryTerminatingSlash() {
        // Stripping only one slash made wellKnownPath and wellKnownUrl disagree on a doubled
        // slash — the exact invariant this pair is supposed to hold.
        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/mcp//")))
                .isEqualTo("/.well-known/oauth-protected-resource/mcp");
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/mcp//"))
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void wellKnownPath_preservesPercentEncodedOctets() {
        // getPath() decodes, so "%2F" collapsed to "/" and the derived path named a different
        // resource than the identifier does (RFC 3986 §3.3).
        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/a%2Fb")))
                .isEqualTo("/.well-known/oauth-protected-resource/a%2Fb");
    }

    @Test
    void wellKnownPath_resourceWithDeepPath() {
        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/v2/mcp")))
                .isEqualTo("/.well-known/oauth-protected-resource/v2/mcp");
    }

    @Test
    void wellKnownUrl_returnsFullUrl() {
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com"))
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource");
    }

    @Test
    void wellKnownUrl_pathWithTrailingSlash_stripped() {
        // wellKnownUrl applies its own terminating-slash strip before deriving the path, so a
        // trailing-slash resource URL still resolves to the slash-less well-known document.
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/mcp/"))
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void wellKnownUrl_preservesQueryComponent() {
        // RFC 9728 §3 forms the well-known URI by inserting the well-known string "between the
        // host component and the path and/or query components, if any" — the query is part of
        // the identifier and follows the derived path. A query is legal in a resource
        // indicator: RFC 8707 §2 states the SHOULD NOT and its exception in the same sentence,
        // and RFC 9728 §1.2 carries it forward. Dropping it advertised a document URL for a
        // different identifier than the one the document's "resource" field publishes.
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/mcp?tenant=a"))
                .isEqualTo(
                        "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a");
    }

    @Test
    void wellKnownUrl_queryOnRootResource_insertsSuffixBeforeQuery() {
        // With no path there is no terminating slash to remove: the well-known suffix lands
        // directly after the host and the query follows it.
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com?x=1"))
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource?x=1");
    }

    @Test
    void wellKnownUrl_queryAfterTerminatingSlash_slashStripped() {
        // RFC 9728 §3.1 removes the terminating slash following the host when a path or query
        // is present, so "/?x=1" derives the same document URL as "?x=1".
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/?x=1"))
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource?x=1");
    }

    @Test
    void wellKnownUrl_queryDifferingIdentifiers_deriveDistinctUrls() {
        // Identifiers differing only in their query are distinct resource identities and must
        // advertise distinct PRM URLs — collapsing them would make a document fetched for one
        // identifier name another, the mismatch RFC 9728 §3.3 makes a client discard.
        String a = ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/mcp?tenant=a");
        String b = ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/mcp?tenant=b");
        String bare = ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/mcp");
        assertThat(a).isNotEqualTo(b);
        assertThat(a).isNotEqualTo(bare);
        assertThat(b).isNotEqualTo(bare);
    }

    @Test
    void wellKnownUrl_preservesRawQueryEncoding() {
        // getRawQuery(): a percent-encoded octet in the query is carried through verbatim.
        // Decoding and re-encoding could rewrite it, and the advertised URL would carry a
        // different query than the identifier does.
        assertThat(
                        ProtectedResourceMetadata.wellKnownUrl(
                                "https://api.example.com/mcp?filter=a%2Fb"))
                .isEqualTo(
                        "https://api.example.com/.well-known/oauth-protected-resource/mcp?filter=a%2Fb");
    }

    @Test
    void wellKnownUrl_preservesRawAuthority() {
        // getAuthority() percent-decodes, so an escaped delimiter in the authority derives a
        // structurally different authority. The vehicle is a percent-escape in the registered name
        // (RFC 3986 §3.2.2 admits pct-encoded there), not userinfo: userinfo is now refused at
        // construction and by wellKnownUrl itself, so it can no longer reach this derivation.
        //
        // %3A is ":" — decoding it would turn the reg-name "a%3Ab.example.com" into "a:b.example
        // .com", which reads as host "a" with port "b". Note the escape must be of a *reserved*
        // octet for raw to be the right answer at all: RFC 3986 §6.2.2.2 has a conformant client
        // decode escaped *unreserved* octets before comparing, so preserving those raw would make
        // the derived URL fail to match what the client actually resolves.
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://a%3Ab.example.com/mcp?x=1"))
                .isEqualTo(
                        "https://a%3Ab.example.com/.well-known/oauth-protected-resource/mcp?x=1");
    }

    @Test
    void wellKnownUrl_emptyQuery_derivesQueryLessUrl() {
        // getRawQuery() returns "" (not null) for a bare trailing '?'. RFC 3986 would allow
        // reading an empty query as present-but-empty, but every implementation of this
        // derivation treats it as absent — parity across implementations wins over that reading,
        // so the derived URL carries no '?'.
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/mcp?"))
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void wellKnownPath_ignoresQueryComponent() {
        // Routing stays path-keyed: the query belongs to the full document URL (wellKnownUrl),
        // never to the route the document is served at. One registered route serves the
        // document for every query value.
        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/mcp?tenant=a")))
                .isEqualTo("/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void wellKnownUrl_queryDoesNotWeakenFragmentGate() {
        // A '#' after the query still begins a fragment (RFC 3986 §3.5); preserving the query
        // must not loosen the fragment rejection.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.wellKnownUrl(
                                        "https://api.example.com/mcp?tenant=a#x"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a fragment component");
    }

    @Test
    void toMap_containsAllRequiredFields() {
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://api.example.com")
                        .authorizationServer("https://auth.example.com")
                        .scopes(List.of("read:data", "write:data"))
                        .build();

        Map<String, Object> doc = prm.toMap();
        assertThat(doc).containsKey("resource");
        assertThat(doc).containsKey("authorization_servers");
        assertThat(doc).containsKey("bearer_methods_supported");
        assertThat(doc).containsKey("scopes_supported");
    }

    @Test
    void toMap_authorizationServersIsList() {
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://api.example.com")
                        .authorizationServer("https://auth.example.com")
                        .build();
        Object as = prm.toMap().get("authorization_servers");
        assertThat(as).asInstanceOf(LIST).containsExactly("https://auth.example.com");
    }

    @Test
    void toMap_bearerMethodsIsHeader() {
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://api.example.com")
                        .authorizationServer("https://auth.example.com")
                        .build();
        assertThat(prm.toMap().get("bearer_methods_supported"))
                .asInstanceOf(LIST)
                .containsExactly("header");
    }

    @Test
    void builder_requiresResource() {
        assertThatNullPointerException()
                .isThrownBy(
                        () ->
                                ProtectedResourceMetadata.builder()
                                        .authorizationServer("https://auth.example.com")
                                        .build());
    }

    @Test
    void builder_requiresAuthorizationServer() {
        assertThatNullPointerException()
                .isThrownBy(
                        () ->
                                ProtectedResourceMetadata.builder()
                                        .resource("https://api.example.com")
                                        .build());
    }

    @Test
    void toMap_isUnmodifiable() {
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://api.example.com")
                        .authorizationServer("https://auth.example.com")
                        .build();
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> prm.toMap().put("extra", "value"));
    }

    @Test
    void wellKnownUrl_trailingSlash_stripped() {
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/"))
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource");
    }

    @Test
    void toJson_producesValidJson() {
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://api.example.com")
                        .authorizationServer("https://auth.example.com")
                        .scopes(List.of("read:data", "write:data"))
                        .build();
        String json = prm.toJson();
        assertThat(json).contains("\"resource\":\"https://api.example.com\"");
        assertThat(json).contains("\"authorization_servers\":[\"https://auth.example.com\"]");
        assertThat(json).contains("\"scopes_supported\":[\"read:data\",\"write:data\"]");
    }

    @Test
    void getters_returnConstructedValues() {
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://api.example.com")
                        .authorizationServer("https://auth.example.com")
                        .scopes(List.of("read:data"))
                        .build();
        assertThat(prm.getResource()).isEqualTo("https://api.example.com");
        assertThat(prm.getAuthorizationServers()).containsExactly("https://auth.example.com");
        assertThat(prm.getBearerMethodsSupported()).containsExactly("header");
        assertThat(prm.getScopesSupported()).containsExactly("read:data");
    }
}
