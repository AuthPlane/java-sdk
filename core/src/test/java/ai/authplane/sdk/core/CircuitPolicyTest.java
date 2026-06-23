package ai.authplane.sdk.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;

import org.junit.jupiter.api.Test;

import ai.authplane.sdk.core.errors.TokenExchangeException;
import ai.authplane.sdk.core.fetching.ssrf.SsrfException;

class CircuitPolicyTest {

    @Test
    void ssrf_doesNotTrip() {
        assertThat(CircuitPolicy.shouldTrip(new SsrfException("blocked"))).isFalse();
    }

    @Test
    void oauthNoCircuitErrors_doNotTrip() {
        for (String code :
                new String[] {
                    "invalid_grant",
                    "invalid_scope",
                    "invalid_request",
                    "consent_required",
                    "interaction_required",
                    "invalid_dpop_proof",
                    "unsupported_grant_type"
                }) {
            assertThat(CircuitPolicy.shouldTrip(new TokenExchangeException("x", code)))
                    .as(code)
                    .isFalse();
        }
    }

    @Test
    void invalidClientAndUnauthorizedTrip() {
        assertThat(CircuitPolicy.shouldTrip(new TokenExchangeException("bad", "invalid_client")))
                .isTrue();
        assertThat(
                        CircuitPolicy.shouldTrip(
                                new TokenExchangeException("no", "unauthorized_client")))
                .isTrue();
    }

    @Test
    void serverErrorOAuthCodeTripsEvenWhenHttpWas4xx() {
        assertThat(CircuitPolicy.shouldTrip(new TokenExchangeException("desc", "server_error")))
                .isTrue();
    }

    @Test
    void unknownOAuthCodeInBody_doesNotTrip() {
        assertThat(CircuitPolicy.shouldTrip(new TokenExchangeException("slow", "slow_down")))
                .isFalse();
    }

    @Test
    void nullOauthError_trips() {
        assertThat(CircuitPolicy.shouldTrip(new TokenExchangeException("parse failed", null)))
                .isTrue();
    }

    @Test
    void wrappedException_unwrapsCause() {
        IOException io = new IOException("reset");
        TokenExchangeException wrapper =
                new TokenExchangeException("Client credentials grant failed: reset", null, io);
        assertThat(CircuitPolicy.shouldTrip(wrapper)).isTrue();
    }

    @Test
    void oauthPostHttp_io_5xxTrips_4xxDoesNotExcept401() {
        assertThat(
                        CircuitPolicy.shouldTrip(
                                new IOException("OAuth POST failed: HTTP 503 from https://x")))
                .isTrue();
        assertThat(
                        CircuitPolicy.shouldTrip(
                                new IOException("OAuth POST failed: HTTP 400 from https://x")))
                .isFalse();
        assertThat(
                        CircuitPolicy.shouldTrip(
                                new IOException("OAuth POST failed: HTTP 401 from https://x")))
                .isTrue();
    }
}
