package ai.authplane.sdk.core.prm;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.nimbusds.jose.util.JSONObjectUtils;

/**
 * Builds and represents a RFC 9728 Protected Resource Metadata document.
 *
 * <p>Serve the document at the well-known URL computed by {@link #wellKnownPath(URI)}.
 *
 * <p>Example:
 *
 * <pre>{@code
 * ProtectedResourceMetadata prm = ProtectedResourceMetadata.builder()
 *     .resource("https://api.example.com")
 *     .authorizationServer("https://auth.example.com")
 *     .scopes(List.of("read:data", "write:data"))
 *     .build();
 *
 * // Serve prm.toMap() as JSON at prm.wellKnownPath()
 * String path = ProtectedResourceMetadata.wellKnownPath(URI.create("https://api.example.com"));
 * // path = "/.well-known/oauth-protected-resource"
 * }</pre>
 */
public final class ProtectedResourceMetadata {

    private static final String WELL_KNOWN_PREFIX = "/.well-known/oauth-protected-resource";

    private final String resource;
    private final List<String> authorizationServers;
    private final List<String> bearerMethodsSupported;
    private final List<String> scopesSupported;

    private ProtectedResourceMetadata(
            String resource,
            List<String> authorizationServers,
            List<String> bearerMethodsSupported,
            List<String> scopesSupported) {
        this.resource = resource;
        this.authorizationServers = List.copyOf(authorizationServers);
        this.bearerMethodsSupported = List.copyOf(bearerMethodsSupported);
        this.scopesSupported = List.copyOf(scopesSupported);
    }

    // -----------------------------------------------------------------------
    // Well-known path derivation
    // -----------------------------------------------------------------------

    /**
     * Computes the URL path at which this resource server should serve its PRM document.
     *
     * <p>The path is derived from the resource URI by inserting {@code
     * /.well-known/oauth-protected-resource} after the authority:
     *
     * <pre>
     * "https://api.example.com"        → "/.well-known/oauth-protected-resource"
     * "https://api.example.com/mcp"    → "/.well-known/oauth-protected-resource/mcp"
     * "https://api.example.com/mcp/"   → "/.well-known/oauth-protected-resource/mcp"
     * "https://api.example.com/mcp//"  → "/.well-known/oauth-protected-resource/mcp"
     * "https://api.example.com/v2/mcp" → "/.well-known/oauth-protected-resource/v2/mcp"
     * "https://api.example.com/a%2Fb"  → "/.well-known/oauth-protected-resource/a%2Fb"
     * </pre>
     *
     * <p>Per RFC 9728 §3.1 every terminating slash of the resource path is stripped when deriving
     * the well-known path; it does not affect the resource identifier itself. The derivation reads
     * the raw (percent-encoded) path, so an encoded octet such as {@code %2F} is carried through
     * verbatim rather than decoded into a path separator — decoding it would name a different path
     * than the resource identifier does.
     *
     * <p>The returned value is the URL <em>path</em> only — the route at which the document is
     * served. A query component of the resource identifier is never part of it: RFC 9728 §3 inserts
     * the well-known string "between the host component and the path and/or query components", so
     * the query follows the derived path in the full document URL (see {@link
     * #wellKnownUrl(String)}) but does not select a different route. Routing stays path-keyed, so
     * identifiers differing only by query share one registered route serving one document. Serving
     * distinct documents per query value is not supported: RFC 9728 §3.3 requires a client to
     * discard a response whose {@code resource} member differs from the identifier it derived the
     * request from, so any query value the shared document's {@code resource} was not built for
     * fails that client-side check.
     *
     * @param resourceUri the resource server URI; must be hierarchical and carry a scheme and an
     *     authority
     * @return the URL path (including leading slash) where the PRM should be served
     * @throws IllegalArgumentException if {@code resourceUri} is opaque, has no scheme, has no
     *     authority, or carries a fragment component
     */
    public static String wellKnownPath(URI resourceUri) {
        // Backstop only: the fragment is rejected at construction, so a resource built through
        // AuthplaneClient.resource() or this class's builder can never reach here carrying one.
        // Kept because these helpers are public and are called on the 401 challenge path, where a
        // silently dropped fragment would publish a document that names a different identifier.
        //
        // It runs before requireDerivable because the two answer different questions: a fragment
        // is unconditionally illegal (RFC 8707 §2), while non-derivability is a limitation of this
        // helper. An identifier that is both — "urn:example:api#secret" — should be reported for
        // the fragment, not for the URN, and reporting the fragment is also what keeps it out of
        // the message. Called unconditionally: requireNoFragment returns on the no-'#' path, and
        // gating on getRawFragment() would be the one place where the parsed-URI view and the raw
        // string could disagree about whether there is a fragment at all.
        requireNoFragment(resourceUri.toString());
        requireValidQuery(resourceUri.toString());
        requireDerivable(resourceUri);

        // Read the raw path: URI.getPath() percent-decodes, which would turn a resource
        // identifier of ".../a%2Fb" into the well-known path ".../a/b" — a different path than
        // the identifier names, and the silent rewrite this derivation exists to avoid.
        String path = resourceUri.getRawPath();
        if (path == null || path.isEmpty()) {
            return WELL_KNOWN_PREFIX;
        }

        // Strip every terminating slash before deriving the well-known path (RFC 9728 §3.1):
        // the resource identity is preserved elsewhere, but the derived .well-known path must
        // not carry a trailing slash ("/mcp/" and "/mcp//" both → ".../mcp"). Stripping only one
        // would make this helper and wellKnownUrl disagree on a doubled slash.
        String derivedPath = path.replaceAll("/+$", "");
        if (derivedPath.isEmpty()) {
            return WELL_KNOWN_PREFIX;
        }

        // Strip leading slash — WELL_KNOWN_PREFIX already starts with /
        String cleanPath = derivedPath.startsWith("/") ? derivedPath.substring(1) : derivedPath;
        return WELL_KNOWN_PREFIX + "/" + cleanPath;
    }

    /**
     * Computes the full URL of the PRM document for the given resource URI.
     *
     * <p>The path component is derived by {@link #wellKnownPath(URI)}, so both helpers agree by
     * construction: the slash stripping happens in exactly one place.
     *
     * <p>A query component of the resource identifier is preserved: RFC 9728 §3 forms the
     * well-known URI by inserting the well-known string "between the host component and the path
     * and/or query components, if any", so the query follows the derived path. A resource
     * identifier may legitimately carry one — RFC 8707 §2 states the SHOULD NOT and its exception
     * in the same sentence, and RFC 9728 §1.2 carries that forward. Dropping it would advertise a
     * document URL for a different identifier than the one this resource publishes in its {@code
     * resource} field.
     *
     * <pre>
     * "https://api.example.com/mcp?tenant=a" → "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a"
     * "https://api.example.com?x=1"          → "https://api.example.com/.well-known/oauth-protected-resource?x=1"
     * "https://api.example.com/?x=1"         → "https://api.example.com/.well-known/oauth-protected-resource?x=1"
     * </pre>
     *
     * <p>The last two agree because RFC 9728 §3.1 removes the terminating slash following the host
     * when a path or query is present. The raw (percent-encoded) authority and query are carried
     * through verbatim — decoding and re-encoding could rewrite octets and name a different
     * identifier. An empty query (a bare trailing {@code ?}) is treated as absent: the derived URL
     * carries no {@code ?}.
     *
     * @param resourceUri the resource server URI string; must be hierarchical and carry a scheme
     *     and an authority
     * @return the full PRM document URL
     * @throws IllegalArgumentException if {@code resourceUri} is opaque, has no scheme, has no
     *     authority, carries userinfo, carries a fragment component, or carries a query outside the
     *     RFC 3986 §3.4 grammar
     */
    public static String wellKnownUrl(String resourceUri) {
        // Before URI.create: an identifier that is both malformed and fragment-bearing should
        // report the fragment, which is the illegal part, rather than a wrapped URISyntaxException.
        // requireDerivable is left to wellKnownPath — calling it here as well only duplicated the
        // answer.
        //
        // All four construction gates run here, not two. The reason the backstops exist at all is
        // that this method is public and reachable with a string no constructor ever saw, and that
        // reason does not distinguish between them: without requireNoUserinfo,
        // wellKnownUrl("https://svc:pw@h/mcp") still splices a credential into the URL this SDK
        // publishes in a 401 challenge.
        requireNoFragment(resourceUri);
        requireScheme(resourceUri);
        requireNoUserinfo(resourceUri);
        requireValidQuery(resourceUri);
        URI uri = URI.create(resourceUri);
        // getRawAuthority(): the raw-preservation rule applies to every component, the authority
        // included. getAuthority() percent-decodes, so "u%40b@host" derived "u@b@host" — an
        // authority structurally different from the one the identifier names.
        String url = uri.getScheme() + "://" + uri.getRawAuthority() + wellKnownPath(uri);
        // Preserve the query component (RFC 9728 §3: the well-known string is inserted between
        // the host and "the path and/or query components, if any"). Raw form, so the encoding is
        // exactly what the operator configured. An empty query (a bare trailing '?', for which
        // getRawQuery() returns "") is treated as absent: RFC 3986 would allow reading it as
        // present-but-empty, but on *this* sub-case — an empty query — the family agrees on the
        // query-less URL, and parity wins over that reading. It is only the empty-query reading
        // that is settled: for a non-empty query the implementations still differ, which is
        // tracked rather than asserted here.
        String query = uri.getRawQuery();
        return query == null || query.isEmpty() ? url : url + "?" + query;
    }

    /**
     * Rejects a resource identifier that carries a URI fragment component.
     *
     * <p>RFC 8707 §2: "The URI MUST NOT include a fragment component." RFC 9728 §1.2 restates it
     * for the identifier a PRM document names.
     *
     * <p>The check runs on the raw string rather than on a parsed {@link URI} because {@link URI}
     * is exactly what hides the defect: it splits the fragment off, so {@code
     * https://api.example.com/mcp#x} derives the well-known URL of {@code
     * https://api.example.com/mcp} while the document publishes the identifier verbatim. The served
     * document's {@code resource} then disagrees with the URL it was fetched from, and RFC 9728
     * §3.3 requires a conformant client to discard the response — an interop failure with no
     * server-side error to notice.
     *
     * <p>Scanning for the character is precise: an unescaped {@code #} always begins a fragment
     * (RFC 3986 §3.5), and a literal {@code #} inside a path is spelled {@code %23}, so {@code
     * https://api.example.com/a%23b} is fragment-free and passes.
     *
     * <p>This is the construction-time gate. It is called from every path that accepts an
     * operator-configured identifier: {@link Builder#build()}, the {@code AuthplaneResource}
     * constructor (which every resource reaches), and {@code AuthplaneClient.resource(...)} — the
     * last one redundant for the guarantee but worth the stack trace, since it fails at the line
     * the operator wrote. Gating only in the derivation helpers above would defer the failure to
     * {@code prmUrl()}, i.e. into a 401 response path, turning a configuration error into a 500 at
     * the worst possible moment.
     *
     * @param resourceUri the resource identifier, as configured by the operator
     * @throws IllegalArgumentException if the identifier carries a fragment component
     */
    public static void requireNoFragment(String resourceUri) {
        // AuthplaneClient.resource(...) two frames up reports this condition as a
        // NullPointerException with a message; this is public API and should not report it as a
        // bare NPE from indexOf.
        Objects.requireNonNull(resourceUri, "resourceUri must not be null");
        if (resourceUri.indexOf('#') < 0) {
            return;
        }
        throw new IllegalArgumentException(
                "Resource identifier \""
                        + elideSecrets(resourceUri)
                        + "\" (fragment and any userinfo elided) must not include a fragment"
                        + " component (RFC 8707 §2, RFC 9728 §1.2). The fragment is dropped when"
                        + " the Protected Resource Metadata URL is derived, so the published"
                        + " document would name an identifier that its own URL disagrees with, and"
                        + " RFC 9728 §3.3 requires a client to discard such a document. Remove the"
                        + " fragment from the configured resource identifier.");
    }

    /**
     * Rejects a resource identifier whose query component is not a valid RFC 3986 §3.4 query.
     *
     * <p>{@code query = *( pchar / "/" / "?" )}, with {@code pchar = unreserved / pct-encoded /
     * sub-delims / ":" / "@"}. Every octet must therefore be a query character or part of a
     * well-formed two-hex-digit percent-escape. This validates only — nothing is escaped on the
     * operator's behalf, because rewriting the query would change the resource's identity (RFC 3986
     * §6.2.2.2 permits decoding only unreserved octets when comparing identifiers).
     *
     * <p>The query is now a supported part of the identifier and is spliced verbatim into the
     * {@code resource_metadata} value of a {@code WWW-Authenticate} challenge, so an octet outside
     * the production has two ways to do damage, both of which the gate closes:
     *
     * <ul>
     *   <li>A raw non-ASCII octet ships into the header. {@code WwwAuthenticate.escapeQuotedString}
     *       strips control characters and escapes {@code \} and {@code "}; a non-ASCII octet is
     *       none of those. RFC 9110 §5.5 confines field values to US-ASCII (obs-text is deprecated
     *       and recipients treat it opaquely), so the advertised {@code resource_metadata} is not a
     *       URI and two clients decoding those octets differently fetch two different URLs.
     *   <li>Nothing else rejects it at construction. {@link URI} does reject a space, {@code "},
     *       {@code \}, {@code |}, {@code ^}, <code>{</code>, <code>}</code>, {@code &lt;} and
     *       {@code &gt;} — but only when the identifier is finally parsed, which happens in {@code
     *       prmUrl()}, on the 401 response path. {@code resource("…/mcp?a=b c")} constructed
     *       cleanly and then threw out of {@code AuthplaneAuthenticationEntryPoint.commence()}: a
     *       500 in place of the 401. That is verbatim the failure {@link
     *       #requireNoFragment(String)} exists to prevent.
     * </ul>
     *
     * <p>Called from the same four boundaries as {@link #requireNoFragment(String)}. Neither the
     * authority nor the path is gated here, and both carry the same two failure modes listed above:
     * a non-ASCII octet in either ships into the quoted-string, and a path {@link URI} rejects
     * still throws out of {@code prmUrl()} on the 401 response path. Both are pre-existing — the
     * authority and the path were always part of the derived URL, and this change neither widens
     * nor narrows them — so tightening this construction boundary is deliberately deferred to a
     * single follow-up, so that it happens in one step rather than piecemeal. When that follow-up
     * lands, the remedy for the path has to be the same as for the query — reject, do not escape:
     * percent-encoding the path on the operator's behalf would make the derived URL name a
     * different path than the {@code resource} member does.
     *
     * @param resourceUri the resource identifier, as configured by the operator
     * @throws IllegalArgumentException if the identifier's query is not a valid RFC 3986 §3.4 query
     */
    public static void requireValidQuery(String resourceUri) {
        Objects.requireNonNull(resourceUri, "resourceUri must not be null");
        // Cut the fragment first: a '?' after a '#' belongs to the fragment, not the query. In
        // practice requireNoFragment has already rejected any '#' at every call site, but this
        // method is public and answers its own question.
        int fragmentStart = resourceUri.indexOf('#');
        String beforeFragment =
                fragmentStart < 0 ? resourceUri : resourceUri.substring(0, fragmentStart);
        int queryStart = beforeFragment.indexOf('?');
        if (queryStart < 0) {
            return;
        }
        String reason = invalidQueryReason(beforeFragment.substring(queryStart + 1));
        if (reason == null) {
            return;
        }
        throw new IllegalArgumentException(
                "Resource identifier \""
                        + elideQuery(resourceUri)
                        + "\" (query and any userinfo elided) has a query component that is not a"
                        + " valid query per RFC 3986 §3.4: "
                        + reason
                        + ". The query is preserved verbatim into the Protected Resource Metadata"
                        + " URL and from there into the resource_metadata parameter of the"
                        + " WWW-Authenticate challenge, where an octet outside the query production"
                        + " yields a value that is not a URI (RFC 9110 §5.5 confines field values to"
                        + " US-ASCII). Percent-encode the offending octet in the configured resource"
                        + " identifier.");
    }

    /**
     * Reports why {@code query} is not a valid RFC 3986 §3.4 query, or {@code null} when it is. The
     * offending octet is named by position and, when it is not printable ASCII, by code point —
     * printing the character itself would render something that never appeared in the input.
     */
    private static String invalidQueryReason(String query) {
        for (int i = 0; i < query.length(); i++) {
            char c = query.charAt(i);
            if (c == '%') {
                if (i + 2 >= query.length()
                        || !isHexDigit(query.charAt(i + 1))
                        || !isHexDigit(query.charAt(i + 2))) {
                    return "malformed percent-escape at index " + i;
                }
                i += 2;
                continue;
            }
            if (isQueryChar(c)) {
                continue;
            }
            if (c >= 0x20 && c < 0x7F) {
                return "invalid character '" + c + "' at index " + i;
            }
            return String.format(
                    "invalid non-ASCII or control character U+%04X at index %d", (int) c, i);
        }
        return null;
    }

    /**
     * Whether {@code c} may appear literally in a URI query: the pchar set (unreserved, sub-delims,
     * {@code ":"}, {@code "@"}) plus {@code "/"} and {@code "?"} (RFC 3986 §§2.2, 2.3, 3.3, 3.4).
     * Percent-escapes are handled by the caller.
     */
    private static boolean isQueryChar(char c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || "-._~".indexOf(c) >= 0 // unreserved
                || "!$&'()*+,;=".indexOf(c) >= 0 // sub-delims
                || c == ':'
                || c == '@' // pchar extras
                || c == '/'
                || c == '?'; // query extras
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /**
     * Requires the identifier to carry a URI scheme — the absolute-URI requirement of RFC 8707 §2,
     * gated at construction like {@link #requireNoFragment(String)} and {@link
     * #requireValidQuery(String)}.
     *
     * <p>A scheme-less identifier is unconditionally illegal, not merely non-derivable: RFC 8707 §2
     * requires the resource indicator to be an absolute URI, and RFC 3986 §4.3 defines one as
     * always carrying a scheme. Leaving the check to the derivation gate ({@link
     * #wellKnownPath(URI)}) is not enough, because the derivation is not the only sink — {@code
     * AuthplaneResource} splices the identifier's scheme into the DPoP {@code htu} it verifies
     * against, so {@code //api.example.com/mcp} yields the literal binding target {@code
     * null://api.example.com/mcp} and every DPoP-bound request fails with a mismatch that names
     * nothing an operator can act on.
     *
     * <p>Only the scheme is required here. The identifier may still be any absolute URI RFC 8707 §2
     * permits — {@code urn:example:api} constructs; whether it can derive a PRM URL is the
     * derivation gate's question, answered when a derivation is actually asked for.
     *
     * <p>Works on the raw string, like the sibling gates: a scheme is present exactly when a {@code
     * :} appears before any {@code /}, {@code ?} or {@code #} and the text before it matches the
     * RFC 3986 §3.1 scheme production ({@code ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )}).
     *
     * <p>Called from the same construction boundaries as the sibling gates: {@link
     * Builder#build()}, the {@code AuthplaneResource} constructor, and {@code
     * AuthplaneClient.resource(...)}. The derivation-time {@code requireDerivable} stays as the
     * backstop for the public derivation helpers.
     *
     * @param resourceUri the resource identifier, as configured by the operator
     * @throws IllegalArgumentException if the identifier does not begin with a URI scheme
     */
    public static void requireScheme(String resourceUri) {
        Objects.requireNonNull(resourceUri, "resourceUri must not be null");
        if (hasScheme(resourceUri)) {
            return;
        }
        throw new IllegalArgumentException(
                "Resource identifier \""
                        + elideSecrets(resourceUri)
                        + "\" (fragment and any userinfo elided) has no scheme: RFC 8707 §2"
                        + " requires the resource indicator to be an absolute URI, which always"
                        + " begins with a scheme (RFC 3986 §4.3). A scheme-relative or relative"
                        + " reference cannot name the resource: the scheme is spliced into the"
                        + " derived Protected Resource Metadata URL and into the DPoP htu binding"
                        + " target, both of which would read the missing scheme as the literal"
                        + " text \"null\". Prefix the intended scheme (e.g."
                        + " https://api.example.com/mcp).");
    }

    /**
     * Rejects a resource identifier whose authority carries a userinfo component.
     *
     * <p>RFC 9110 §4.2.4 deprecates userinfo in an {@code http} or {@code https} URI and directs a
     * recipient to reject one that carries it; RFC 3986 §3.2.1 warns that it routinely holds a
     * credential in clear text. Here the stakes are higher than for a request target that merely
     * gets logged: the identifier is stored verbatim, published as the {@code resource} member of
     * the Protected Resource Metadata document that RFC 9728 §3 serves to unauthenticated callers,
     * and spliced into the {@code resource_metadata} parameter of the 401 {@code WWW-Authenticate}
     * challenge. A credential in the userinfo is therefore handed to everyone who asks.
     *
     * <p>Rejecting at construction is what makes that guarantee. Eliding the userinfo at each sink
     * only covers the sinks that remember to elide, and every sink added later has to remember
     * again; the error messages keep eliding regardless, because these gates are public and are
     * applied to strings this one never saw.
     *
     * <p>Works on the raw string like the sibling gates, reading the authority as everything
     * between the {@code //} that opens it and the first {@code /} or {@code ?} that closes it. An
     * unescaped {@code @} delimits userinfo there and appears nowhere else in an authority (RFC
     * 3986 §3.2), so a host with a port ({@code https://api.example.com:8443/mcp}) and an IPv6
     * literal ({@code https://[::1]:8443/mcp}) both pass, as does an identifier with no authority
     * at all ({@code urn:example:api}). An empty userinfo ({@code https://@api.example.com/mcp}) is
     * still a userinfo component and is rejected.
     *
     * <p>Called from the same construction boundaries as the sibling gates — {@link
     * Builder#build()}, the {@code AuthplaneResource} constructor, and {@code
     * AuthplaneClient.resource(...)} — after {@link #requireScheme(String)}, so an identifier that
     * is also scheme-relative is reported for the missing scheme, the defect an operator fixes
     * first.
     *
     * <p>The four gates run in the same *set* everywhere but not in the same *order*: the three
     * construction sites run fragment, query, scheme, userinfo, while {@link #wellKnownUrl(String)}
     * runs fragment, scheme, userinfo, query. So an identifier that violates two of them can be
     * reported for a different component depending on the entrypoint. Both reject either way; only
     * the message differs. Unifying the four behind one private gate is tracked.
     *
     * @param resourceUri the resource identifier, as configured by the operator
     * @throws IllegalArgumentException if the identifier's authority carries a userinfo component
     */
    public static void requireNoUserinfo(String resourceUri) {
        Objects.requireNonNull(resourceUri, "resourceUri must not be null");
        // Cut the fragment first: an '@' after a '#' belongs to the fragment, not the authority.
        // requireNoFragment has already rejected any '#' at every call site, but this method is
        // public and answers its own question.
        int fragmentStart = resourceUri.indexOf('#');
        String beforeFragment =
                fragmentStart < 0 ? resourceUri : resourceUri.substring(0, fragmentStart);
        int[] authority = authorityBounds(beforeFragment);
        if (authority == null || beforeFragment.lastIndexOf('@', authority[1] - 1) < authority[0]) {
            return;
        }
        throw new IllegalArgumentException(
                "Resource identifier \""
                        + elideSecrets(resourceUri)
                        + "\" (fragment and any userinfo elided) must not include a userinfo"
                        + " component in its authority: RFC 9110 §4.2.4 deprecates userinfo and"
                        + " directs a recipient to reject a URI carrying it, and RFC 3986 §3.2.1"
                        + " notes it routinely holds a credential in clear text. The identifier is"
                        + " stored verbatim — it is published as the resource member of the"
                        + " Protected Resource Metadata document, which RFC 9728 §3 serves to"
                        + " unauthenticated callers, and spliced into the resource_metadata"
                        + " parameter of the 401 WWW-Authenticate challenge — so the credential"
                        + " would be disclosed to every client that asks. Remove the userinfo from"
                        + " the configured resource identifier (e.g."
                        + " https://api.example.com/mcp) and present the credential in the"
                        + " Authorization header instead.");
    }

    /** Whether {@code resourceUri} begins with an RFC 3986 §3.1 scheme followed by {@code :}. */
    private static boolean hasScheme(String resourceUri) {
        return schemeEnd(resourceUri) >= 0;
    }

    /**
     * Index of the {@code :} terminating the RFC 3986 §3.1 scheme of {@code resourceUri}, or {@code
     * -1} when the string does not begin with a scheme. Only a {@code :} reached through scheme
     * characters alone delimits a scheme, so a {@code :} inside an authority, path or query is
     * never mistaken for one.
     */
    private static int schemeEnd(String resourceUri) {
        for (int i = 0; i < resourceUri.length(); i++) {
            char c = resourceUri.charAt(i);
            if (c == ':') {
                return i > 0 ? i : -1; // non-empty; earlier iterations validated every character
            }
            if (c == '/' || c == '?' || c == '#') {
                return -1; // path, query or fragment began before any ':'
            }
            boolean validSchemeChar =
                    i == 0
                            ? isAlpha(c)
                            : isAlpha(c) || (c >= '0' && c <= '9') || "+-.".indexOf(c) >= 0;
            if (!validSchemeChar) {
                return -1; // not a scheme character, so any later ':' is not a scheme delimiter
            }
        }
        return -1; // no ':' at all
    }

    /**
     * Best-effort authority bounds for {@link #elideSecrets(String)} only, used when {@link
     * #authorityBounds(String)} declines.
     *
     * <p>Anchors on the first {@code "//"} anywhere in the string rather than requiring a valid
     * scheme in front of it, so an identifier the strict helper cannot parse still gets redacted.
     * Never use this for a gate: it will happily find an "authority" inside a query, which is a
     * false rejection there and merely a harmless over-redaction here.
     *
     * @return {@code {start, end}} of the presumed authority, or {@code null} if there is no {@code
     *     "//"} at all — a genuinely opaque identifier such as {@code urn:example:api}, which has
     *     no authority and therefore no userinfo.
     */
    private static int[] bestEffortAuthorityBounds(String beforeFragment) {
        int slashes = beforeFragment.indexOf("//");
        if (slashes < 0) {
            return null;
        }
        int start = slashes + "//".length();
        int end = beforeFragment.length();
        for (int i = start; i < end; i++) {
            char c = beforeFragment.charAt(i);
            if (c == '/' || c == '?') {
                end = i;
                break;
            }
        }
        return new int[] {start, end};
    }

    /**
     * Bounds {@code [start, end)} of the authority component of a fragment-free identifier, or
     * {@code null} when it has none. Shared by {@link #requireNoUserinfo(String)} and {@link
     * #elideSecrets(String)} so the gate and the redactor can never disagree about where the
     * authority is.
     *
     * <p>A leading {@code //} is tested <em>before</em> the {@code ://} of an absolute URI, never
     * the other way round: index 0 cannot be preceded by a scheme, so a scheme-relative reference
     * (RFC 3986 §4.2) opens its authority at index 2 and a later {@code ://} in its path or query
     * is not an authority delimiter. Testing {@code ://} first anchored the authority inside the
     * query of {@code //svc:pw@api.example.com/mcp?next=https://x}, which put the real userinfo
     * before the supposed authority and made the redactor return the credential verbatim.
     *
     * <p>The {@code ://} of an absolute URI is located through {@link #schemeEnd(String)} rather
     * than by searching for the literal, for the same reason in the other direction: an
     * authority-less identifier such as {@code https:example.com/mcp?u=http://x} must not have an
     * authority conjured out of its query.
     */
    private static int[] authorityBounds(String beforeFragment) {
        int start;
        if (beforeFragment.startsWith("//")) {
            start = "//".length();
        } else {
            int schemeColon = schemeEnd(beforeFragment);
            if (schemeColon < 0 || !beforeFragment.startsWith("//", schemeColon + 1)) {
                return null; // opaque or path-relative: no authority
            }
            start = schemeColon + 1 + "//".length();
        }

        int end = beforeFragment.length();
        for (int i = start; i < end; i++) {
            char c = beforeFragment.charAt(i);
            if (c == '/' || c == '?') {
                end = i;
                break;
            }
        }
        return new int[] {start, end};
    }

    private static boolean isAlpha(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    /**
     * {@link #elideSecrets(String)} plus the query, for a message about the query itself — the same
     * reason the fragment is elided from the message about the fragment.
     */
    private static String elideQuery(String resourceUri) {
        String elided = elideSecrets(resourceUri);
        int queryStart = elided.indexOf('?');
        return queryStart < 0 ? elided : elided.substring(0, queryStart);
    }

    /**
     * Renders an identifier for an error message with the two components that should not reach a
     * log removed: the fragment, and the userinfo of the authority. Both are operator-supplied and
     * both routinely carry a credential; the scheme, host and path are what let an operator find
     * the offending configuration.
     *
     * <p>Works on the raw string rather than a parsed {@link URI}, so it is usable on an identifier
     * that does not parse — which is the case these messages most need to describe.
     */
    private static String elideSecrets(String resourceUri) {
        String elided = resourceUri;
        int fragmentStart = elided.indexOf('#');
        if (fragmentStart >= 0) {
            elided = elided.substring(0, fragmentStart);
        }

        // An authority follows a leading "//" in a scheme-relative reference (RFC 3986 §4.2) —
        // exactly the shape the scheme gate rejects — or the "://" of an absolute hierarchical
        // URI. This method must elide the userinfo of either, or the message asserting elision
        // would carry the credential verbatim.
        //
        // The two callers pull in opposite directions and cannot share one helper: the gate must
        // not over-reject, so authorityBounds requires a valid scheme; the redactor must not
        // under-redact, and giving up on a strict miss is precisely under-redacting. An
        // identifier whose scheme does not parse — "1https://svc:pw@host/mcp", or the likelier
        // " https://svc:pw@host/mcp" out of YAML or env, which nothing on the construction path
        // trims — reaches requireScheme and used to ship its credential verbatim in a message
        // ending "(fragment and any userinfo elided)". So on a strict miss, fall back to a
        // best-effort scan. Over-redacting something that is not an authority costs nothing in a
        // message; leaking a password costs everything.
        int[] authority = authorityBounds(elided);
        if (authority == null) {
            authority = bestEffortAuthorityBounds(elided);
        }
        if (authority == null) {
            return elided; // opaque or path-relative: no authority, so no userinfo
        }
        int authorityStart = authority[0];
        int authorityEnd = authority[1];

        // RFC 3986 §3.2.1: '@' is not allowed unescaped inside userinfo, so the last '@' within
        // the authority is its delimiter.
        int userInfoEnd = elided.lastIndexOf('@', authorityEnd - 1);
        if (userInfoEnd < authorityStart) {
            return elided;
        }
        return elided.substring(0, authorityStart) + "***@" + elided.substring(userInfoEnd + 1);
    }

    /**
     * Guards the PRM derivation helpers against identifiers they cannot derive from.
     *
     * <p>RFC 8707 §2 permits a resource indicator that is any absolute URI, and this class stores
     * whatever it is given verbatim — {@code urn:example:api} is a valid resource identifier. But
     * an opaque URI has no authority and no hierarchical path, so there is no PRM URL to publish
     * for it: the derivation would otherwise emit {@code urn://null/.well-known/...} and hand that
     * to the {@code resource_metadata} parameter of the 401 challenge.
     *
     * <p>The scheme is gated for the same reason, and needs its own test: a scheme-relative
     * reference such as {@code //api.example.com/mcp} is neither opaque nor authority-less, so it
     * clears both of the checks above. The derivation then reads a null scheme and emits {@code
     * null://api.example.com/.well-known/oauth-protected-resource/mcp} into that same challenge
     * parameter. RFC 8707 §2 requires the resource indicator to be an absolute URI, and RFC 3986
     * §4.3 defines one as always carrying a scheme, so no legitimate identifier is turned away.
     */
    private static void requireDerivable(URI resourceUri) {
        // Name the requirement this identifier actually fails — a generic both-requirements
        // message reads as though everything is missing, which for "urn:example:api" (a scheme,
        // no hierarchy) points the operator at the wrong half.
        String defect;
        if (resourceUri.isOpaque()) {
            defect = "it is opaque (no hierarchical part follows the scheme)";
        } else if (resourceUri.getScheme() == null) {
            defect = "it has no scheme";
        } else if (resourceUri.getAuthority() == null) {
            defect = "it has no authority";
        } else {
            return;
        }
        throw new IllegalArgumentException(
                "Cannot derive a Protected Resource Metadata URL from \""
                        + elideSecrets(resourceUri.toString())
                        + "\" (any userinfo elided): "
                        + defect
                        + ". PRM derivation requires a hierarchical resource identifier with a"
                        + " scheme and an authority (e.g. https://api.example.com/mcp). The"
                        + " resource identifier itself may be any absolute URI permitted by RFC"
                        + " 8707 §2 and is stored verbatim; only the derivation is restricted.");
    }

    // -----------------------------------------------------------------------
    // Document serialization
    // -----------------------------------------------------------------------

    /**
     * Returns the PRM document as a JSON string, correctly handling strings, arrays, booleans, and
     * special characters.
     */
    public String toJson() {
        return JSONObjectUtils.toJSONString(toMap());
    }

    /**
     * Returns the PRM document as an unmodifiable Map suitable for JSON serialization.
     *
     * <p>Key ordering is deterministic (insertion order via LinkedHashMap).
     */
    public Map<String, Object> toMap() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("resource", resource);
        doc.put("authorization_servers", authorizationServers);
        doc.put("bearer_methods_supported", bearerMethodsSupported);
        doc.put("scopes_supported", scopesSupported);
        return Collections.unmodifiableMap(doc);
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    public String getResource() {
        return resource;
    }

    public List<String> getAuthorizationServers() {
        return authorizationServers;
    }

    public List<String> getBearerMethodsSupported() {
        return bearerMethodsSupported;
    }

    public List<String> getScopesSupported() {
        return scopesSupported;
    }

    // -----------------------------------------------------------------------
    // Builder
    // -----------------------------------------------------------------------

    public static Builder builder() {
        return new Builder();
    }

    /** Builder for constructing {@link ProtectedResourceMetadata} instances. */
    public static final class Builder {

        private String resource;
        private String authorizationServer;
        private List<String> scopes = List.of();

        private Builder() {}

        /** The resource server URI. Must match the {@code aud} claim in tokens. Required. */
        public Builder resource(String resource) {
            this.resource = resource;
            return this;
        }

        /**
         * The Authorization Server issuer URI. Required. Typically the same as the {@code iss}
         * claim in tokens.
         */
        public Builder authorizationServer(String issuer) {
            this.authorizationServer = issuer;
            return this;
        }

        /** The scopes supported by this resource server. */
        public Builder scopes(List<String> scopes) {
            this.scopes = List.copyOf(scopes);
            return this;
        }

        /** Constructs an immutable {@link ProtectedResourceMetadata} instance from this builder. */
        public ProtectedResourceMetadata build() {
            Objects.requireNonNull(resource, "resource is required");
            Objects.requireNonNull(authorizationServer, "authorizationServer is required");
            if (resource.isBlank())
                throw new IllegalArgumentException("resource must not be blank");
            if (authorizationServer.isBlank())
                throw new IllegalArgumentException("authorizationServer must not be blank");
            requireNoFragment(resource);
            requireValidQuery(resource);
            requireScheme(resource);
            requireNoUserinfo(resource);

            return new ProtectedResourceMetadata(
                    resource, List.of(authorizationServer), List.of("header"), scopes);
        }
    }
}
