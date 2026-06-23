package ai.authplane.sdk.core.fetching;

/**
 * Immutable configuration for SSRF protection when fetching remote documents (JWKS, OAuth
 * metadata).
 *
 * <p>Production defaults (use {@link #production()}): ssrfProtection=true, allowHttp=false,
 * allowLocalhost=false, allowPrivateNetworks=false, timeoutSeconds=10
 *
 * <p>Development defaults (use {@link #devMode()}): ssrfProtection=true, allowHttp=true,
 * allowLocalhost=true, allowPrivateNetworks=true, timeoutSeconds=10. Dev mode keeps SSRF protection
 * on (DNS pinning, IP blocklist, cloud-metadata blocking) and only relaxes the three allowlist
 * toggles so a misconfigured dev-mode build deployed to production still benefits from
 * defense-in-depth.
 *
 * <p>IMPORTANT: 169.254.0.0/16 (cloud metadata) and fe80::/10 (link-local IPv6) are ALWAYS blocked,
 * in both production and dev mode. This is not configurable.
 */
public record FetchSettings(
        /**
         * When true, all SSRF protections are active: IP blocklist validation, DNS pinning,
         * HTTPS-only. When false, only cloud metadata ranges are still blocked.
         */
        boolean ssrfProtection,

        /** Allow plain HTTP URLs. Default false. Only set true in dev mode. */
        boolean allowHttp,

        /** Allow loopback addresses (127.x.x.x, ::1). Default false. */
        boolean allowLocalhost,

        /** Allow RFC 1918 private IP ranges. Default false. */
        boolean allowPrivateNetworks,

        /** HTTP request and connect timeout in seconds. Default 10. */
        int timeoutSeconds) {
    /** Production settings — SSRF protection fully enabled. */
    public static FetchSettings production() {
        return new FetchSettings(true, false, false, false, 10);
    }

    /**
     * Dev mode settings — SSRF protection stays enabled (DNS pinning, IP blocklist, cloud-metadata
     * blocking) but HTTP, loopback, and RFC 1918 private addresses are allowed. Defense-in-depth
     * survives a dev-mode build accidentally reaching production.
     */
    public static FetchSettings devMode() {
        return new FetchSettings(true, true, true, true, 10);
    }

    /**
     * Returns the appropriate settings based on a boolean dev mode flag.
     *
     * @param devMode if true returns {@link #devMode()}, else {@link #production()}
     */
    public static FetchSettings fromDevMode(boolean devMode) {
        return devMode ? devMode() : production();
    }
}
