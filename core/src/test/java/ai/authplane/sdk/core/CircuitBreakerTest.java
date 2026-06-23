package ai.authplane.sdk.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for CircuitBreaker state machine.
 *
 * <p>CircuitBreaker is package-private, so this test must be in the same package.
 */
class CircuitBreakerTest {

    private CircuitBreaker cb;

    @BeforeEach
    void setUp() {
        // threshold=3, cooldown=1 second
        cb = new CircuitBreaker(3, 1);
    }

    // -----------------------------------------------------------------------
    // Initial state
    // -----------------------------------------------------------------------

    @Test
    void initialState_isClosed() {
        assertThat(cb.state()).isEqualTo(CircuitBreaker.State.CLOSED);
        assertThat(cb.failureCount()).isEqualTo(0);
    }

    @Test
    void allowRequest_inClosedState_returnsTrue() {
        assertThat(cb.allowRequest()).isTrue();
    }

    // -----------------------------------------------------------------------
    // Stays CLOSED on successes
    // -----------------------------------------------------------------------

    @Test
    void recordSuccess_inClosedState_staysClosed() {
        cb.recordSuccess();
        cb.recordSuccess();
        cb.recordSuccess();

        assertThat(cb.state()).isEqualTo(CircuitBreaker.State.CLOSED);
        assertThat(cb.failureCount()).isEqualTo(0);
    }

    @Test
    void recordSuccess_resetsFailureCount() {
        cb.recordFailure();
        cb.recordFailure();
        assertThat(cb.failureCount()).isEqualTo(2);

        cb.recordSuccess();
        assertThat(cb.failureCount()).isEqualTo(0);
        assertThat(cb.state()).isEqualTo(CircuitBreaker.State.CLOSED);
    }

    // -----------------------------------------------------------------------
    // Opens after threshold failures
    // -----------------------------------------------------------------------

    @Test
    void recordFailure_belowThreshold_staysClosed() {
        cb.recordFailure();
        cb.recordFailure();

        assertThat(cb.state()).isEqualTo(CircuitBreaker.State.CLOSED);
        assertThat(cb.failureCount()).isEqualTo(2);
    }

    @Test
    void recordFailure_atThreshold_transitionsToOpen() {
        cb.recordFailure();
        cb.recordFailure();
        cb.recordFailure();

        assertThat(cb.state()).isEqualTo(CircuitBreaker.State.OPEN);
    }

    @Test
    void recordFailure_aboveThreshold_remainsOpen() {
        for (int i = 0; i < 5; i++) {
            cb.recordFailure();
        }
        assertThat(cb.state()).isEqualTo(CircuitBreaker.State.OPEN);
    }

    // -----------------------------------------------------------------------
    // Rejects requests when OPEN
    // -----------------------------------------------------------------------

    @Test
    void allowRequest_inOpenState_beforeCooldown_returnsFalse() {
        // Open the circuit
        for (int i = 0; i < 3; i++) {
            cb.recordFailure();
        }
        assertThat(cb.state()).isEqualTo(CircuitBreaker.State.OPEN);

        // Should reject immediately (cooldown is 1 second)
        assertThat(cb.allowRequest()).isFalse();
    }

    // -----------------------------------------------------------------------
    // Transitions to HALF_OPEN after cooldown
    // -----------------------------------------------------------------------

    @Test
    void allowRequest_inOpenState_afterCooldown_transitionsToHalfOpen() throws Exception {
        // Use a very short cooldown for this test
        CircuitBreaker shortCb = new CircuitBreaker(1, 0);
        shortCb.recordFailure(); // Opens immediately (threshold=1)
        assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.OPEN);

        // cooldown is 0 seconds, so it should transition immediately
        Thread.sleep(10); // tiny wait to ensure time has passed
        assertThat(shortCb.allowRequest()).isTrue();
        assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.HALF_OPEN);
    }

    // -----------------------------------------------------------------------
    // Closes on success in HALF_OPEN
    // -----------------------------------------------------------------------

    @Test
    void recordSuccess_inHalfOpen_transitionsToClosed() throws Exception {
        CircuitBreaker shortCb = new CircuitBreaker(1, 0);
        shortCb.recordFailure(); // threshold=1 → OPEN
        Thread.sleep(10);
        shortCb.allowRequest(); // cooldown=0 → HALF_OPEN

        assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.HALF_OPEN);

        shortCb.recordSuccess();

        assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.CLOSED);
        assertThat(shortCb.failureCount()).isEqualTo(0);
    }

    // -----------------------------------------------------------------------
    // Reopens on failure in HALF_OPEN
    // -----------------------------------------------------------------------

    @Test
    void recordFailure_inHalfOpen_transitionsToOpen() throws Exception {
        CircuitBreaker shortCb = new CircuitBreaker(1, 0);
        shortCb.recordFailure(); // threshold=1 → OPEN
        Thread.sleep(10);
        shortCb.allowRequest(); // cooldown=0 → HALF_OPEN

        assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.HALF_OPEN);

        shortCb.recordFailure();

        assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.OPEN);
    }

    // -----------------------------------------------------------------------
    // HALF_OPEN allows requests
    // -----------------------------------------------------------------------

    @Test
    void allowRequest_inHalfOpen_rejectsSecondProbeUntilRecorded() throws Exception {
        CircuitBreaker shortCb = new CircuitBreaker(1, 0);
        shortCb.recordFailure();
        Thread.sleep(10);

        // First probe is admitted and transitions to HALF_OPEN.
        assertThat(shortCb.allowRequest()).isTrue();
        assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.HALF_OPEN);

        // A second probe while one is in flight must be rejected (single-flight).
        assertThat(shortCb.allowRequest()).isFalse();
    }

    // -----------------------------------------------------------------------
    // Concurrency
    // -----------------------------------------------------------------------

    @Test
    void allowRequest_inHalfOpen_admitsOnlyOneConcurrentProbe() throws Exception {
        CircuitBreaker shortCb = new CircuitBreaker(1, 0);
        shortCb.recordFailure(); // threshold=1 → OPEN
        Thread.sleep(10); // cooldown=0 has elapsed

        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger admitted = new AtomicInteger(0);

        for (int i = 0; i < threads; i++) {
            pool.submit(
                    () -> {
                        try {
                            start.await();
                            if (shortCb.allowRequest()) admitted.incrementAndGet();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    });
        }
        start.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(5, TimeUnit.SECONDS)).isTrue();

        assertThat(admitted.get()).isEqualTo(1);
        assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.HALF_OPEN);
    }

    @Test
    void recordFailure_inHalfOpen_resetsProbe_soNextCooldownProbesAgain() throws Exception {
        CircuitBreaker shortCb = new CircuitBreaker(1, 0);
        shortCb.recordFailure(); // → OPEN
        Thread.sleep(10);
        assertThat(shortCb.allowRequest()).isTrue(); // probe 1 → HALF_OPEN
        shortCb.recordFailure(); // failed probe → OPEN, probe slot released
        assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.OPEN);

        Thread.sleep(10);
        // The probe slot was released, so the next cooldown admits a fresh probe.
        assertThat(shortCb.allowRequest()).isTrue();
        assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.HALF_OPEN);
    }

    // -----------------------------------------------------------------------
    // execute() — encapsulated admit/run/record cycle (slot cannot leak)
    // -----------------------------------------------------------------------

    private static final Predicate<Throwable> ALWAYS_TRIPS = t -> true;
    private static final Predicate<Throwable> NEVER_TRIPS = t -> false;

    @Test
    void execute_inClosed_success_returnsValueAndStaysClosed() throws Exception {
        String result = cb.execute(() -> "ok", ALWAYS_TRIPS);

        assertThat(result).isEqualTo("ok");
        assertThat(cb.state()).isEqualTo(CircuitBreaker.State.CLOSED);
    }

    @Test
    void execute_inClosed_trippingError_countsTowardOpen() {
        for (int i = 0; i < 3; i++) {
            assertThatThrownBy(
                            () ->
                                    cb.execute(
                                            () -> {
                                                throw new RuntimeException("boom");
                                            },
                                            ALWAYS_TRIPS))
                    .isInstanceOf(RuntimeException.class);
        }
        assertThat(cb.state()).isEqualTo(CircuitBreaker.State.OPEN);
    }

    @Test
    void execute_inClosed_nonTrippingError_doesNotOpen_andResetsStreak() {
        cb.recordFailure();
        cb.recordFailure();
        assertThat(cb.failureCount()).isEqualTo(2);

        // A non-tripping error means the AS answered — treat as healthy.
        assertThatThrownBy(
                        () ->
                                cb.execute(
                                        () -> {
                                            throw new RuntimeException("invalid_scope");
                                        },
                                        NEVER_TRIPS))
                .isInstanceOf(RuntimeException.class);

        assertThat(cb.state()).isEqualTo(CircuitBreaker.State.CLOSED);
        assertThat(cb.failureCount()).isEqualTo(0);
    }

    @Test
    void execute_whenOpenBeforeCooldown_throwsCircuitOpen_withoutInvokingCall() {
        for (int i = 0; i < 3; i++) {
            cb.recordFailure();
        }
        assertThat(cb.state()).isEqualTo(CircuitBreaker.State.OPEN);

        AtomicBoolean invoked = new AtomicBoolean(false);
        assertThatThrownBy(
                        () ->
                                cb.execute(
                                        () -> {
                                            invoked.set(true);
                                            return "x";
                                        },
                                        ALWAYS_TRIPS))
                .isInstanceOf(CircuitOpenException.class);

        assertThat(invoked).isFalse();
        assertThat(cb.state()).isEqualTo(CircuitBreaker.State.OPEN);
    }

    @Test
    void execute_inHalfOpen_nonTrippingError_closesBreaker_andReleasesProbe() throws Exception {
        CircuitBreaker shortCb = new CircuitBreaker(1, 0);
        shortCb.recordFailure(); // threshold=1 → OPEN
        Thread.sleep(10); // cooldown=0 elapsed

        // The probe call fails with a non-tripping error (AS answered with a business error).
        // The breaker must record success, close, and release the probe slot — not wedge shut.
        assertThatThrownBy(
                        () ->
                                shortCb.execute(
                                        () -> {
                                            throw new RuntimeException("invalid_grant");
                                        },
                                        NEVER_TRIPS))
                .isInstanceOf(RuntimeException.class);

        assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.CLOSED);
        assertThat(shortCb.allowRequest()).isTrue();
    }

    @Test
    void execute_inHalfOpen_trippingError_reopens_andReleasesProbe() throws Exception {
        CircuitBreaker shortCb = new CircuitBreaker(1, 0);
        shortCb.recordFailure(); // → OPEN
        Thread.sleep(10);

        assertThatThrownBy(
                        () ->
                                shortCb.execute(
                                        () -> {
                                            throw new RuntimeException("server_error");
                                        },
                                        ALWAYS_TRIPS))
                .isInstanceOf(RuntimeException.class);

        assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.OPEN);

        Thread.sleep(10);
        // Slot released on the failed probe → next cooldown admits a fresh probe.
        assertThat(shortCb.allowRequest()).isTrue();
    }

    @Test
    void execute_inHalfOpen_success_closesBreaker() throws Exception {
        CircuitBreaker shortCb = new CircuitBreaker(1, 0);
        shortCb.recordFailure(); // → OPEN
        Thread.sleep(10);

        String result = shortCb.execute(() -> "ok", ALWAYS_TRIPS);

        assertThat(result).isEqualTo("ok");
        assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.CLOSED);
    }

    @Test
    void execute_concurrentProbeRejected_doesNotCloseInflightProbe() throws Exception {
        CircuitBreaker shortCb = new CircuitBreaker(1, 0);
        shortCb.recordFailure(); // → OPEN
        Thread.sleep(10);

        CountDownLatch probeInFlight = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            // Probe 1: admitted, signals it is in flight, then blocks until released.
            pool.submit(
                    () ->
                            shortCb.execute(
                                    () -> {
                                        probeInFlight.countDown();
                                        release.await();
                                        return "ok";
                                    },
                                    ALWAYS_TRIPS));

            assertThat(probeInFlight.await(5, TimeUnit.SECONDS)).isTrue();
            assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.HALF_OPEN);

            // A concurrent execute() while the probe is in flight must be rejected and must NOT
            // close the breaker or release probe 1's slot.
            assertThatThrownBy(() -> shortCb.execute(() -> "second", ALWAYS_TRIPS))
                    .isInstanceOf(CircuitOpenException.class);
            assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.HALF_OPEN);
        } finally {
            release.countDown();
            pool.shutdown();
            assertThat(pool.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        }

        // Probe 1 succeeded → breaker closes.
        assertThat(shortCb.state()).isEqualTo(CircuitBreaker.State.CLOSED);
    }
}
