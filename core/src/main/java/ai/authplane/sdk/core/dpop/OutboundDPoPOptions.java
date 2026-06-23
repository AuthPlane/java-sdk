package ai.authplane.sdk.core.dpop;

import java.util.Objects;

/**
 * Client-scoped outbound DPoP configuration.
 *
 * @param provider proof generator and nonce manager shared by the client
 */
public record OutboundDPoPOptions(DPoPProvider provider) {

    public OutboundDPoPOptions {
        Objects.requireNonNull(provider, "provider must not be null");
    }
}
