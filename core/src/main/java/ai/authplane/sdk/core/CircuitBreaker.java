package ai.authplane.sdk.core;

import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import java.util.logging.Logger;

/**
 * Simple circuit breaker state machine for protecting AS calls.
 *
 * <p>States: CLOSED → OPEN → HALF_OPEN → CLOSED (on success) or OPEN (on failure).
 *
 * <p>Package-private — internal resilience component used by {@link AuthplaneClient}.
 */
final class CircuitBreaker {

    private static final Logger LOG = Logger.getLogger(CircuitBreaker.class.getName());

    enum State {
        CLOSED,
        OPEN,
        HALF_OPEN
    }

    private final int failureThreshold;
    private final long cooldownMillis;

    private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);
    private final AtomicInteger failureCount = new AtomicInteger(0);
    private final AtomicLong openedAt = new AtomicLong(0);

    /**
     * Single-flight gate for the HALF_OPEN probe. Exactly one caller may hold this at a time; it is
     * released when the probe completes (success or failure) so the next cooldown can probe again.
     */
    private final AtomicBoolean probeInFlight = new AtomicBoolean(false);

    CircuitBreaker(int failureThreshold, int cooldownSeconds) {
        this.failureThreshold = failureThreshold;
        this.cooldownMillis = cooldownSeconds * 1000L;
    }

    /**
     * Runs an AS call under the breaker, encapsulating the admit/run/record cycle so the
     * single-flight probe slot can never leak.
     *
     * <p>The call is admitted per {@link #allowRequest()}; if not admitted a {@link
     * CircuitOpenException} is thrown <em>before</em> the call runs (so a rejection never affects
     * breaker state). Once admitted, exactly one outcome is recorded internally: success on normal
     * return, otherwise {@code trips.test(error)} decides — a tripping error counts as a failure, a
     * non-tripping one (the AS answered, e.g. an OAuth business error) is recorded as success. In
     * the CLOSED state that success deliberately resets the consecutive-failure count: a responsive
     * AS clears the streak even when the individual call was a business rejection. The original
     * exception is always rethrown. A JVM {@link Error} is not caught — it propagates without
     * touching breaker state.
     *
     * @param call the AS operation to run
     * @param trips returns {@code true} if the exception indicates the AS itself is unhealthy
     * @param <T> the call's result type
     * @return the call's result
     * @throws CircuitOpenException if the call is not admitted (the call is not invoked)
     * @throws Exception whatever {@code call} throws (after the outcome is recorded)
     */
    <T> T execute(Callable<T> call, Predicate<Throwable> trips) throws Exception {
        if (!allowRequest()) {
            throw new CircuitOpenException();
        }
        try {
            T result = call.call();
            recordSuccess();
            return result;
        } catch (Exception e) {
            if (trips.test(e)) {
                recordFailure();
            } else {
                recordSuccess();
            }
            throw e;
        }
    }

    /** Returns true if the call should be allowed through. */
    boolean allowRequest() {
        State current = state.get();
        if (current == State.CLOSED) return true;
        if (current == State.OPEN) {
            if (System.currentTimeMillis() - openedAt.get() < cooldownMillis) {
                return false;
            }
            // Cooldown elapsed: admit a single probe. Claiming the probe slot is the gate —
            // only the winner proceeds, and it then publishes HALF_OPEN.
            if (!probeInFlight.compareAndSet(false, true)) {
                return false;
            }
            state.compareAndSet(State.OPEN, State.HALF_OPEN);
            LOG.info("Circuit breaker transitioning to HALF_OPEN");
            return true;
        }
        // HALF_OPEN — admit only if no probe is currently in flight.
        return probeInFlight.compareAndSet(false, true);
    }

    /** Records a successful call. */
    void recordSuccess() {
        State current = state.get();
        if (current == State.HALF_OPEN) {
            if (state.compareAndSet(State.HALF_OPEN, State.CLOSED)) {
                failureCount.set(0);
                probeInFlight.set(false);
                LOG.info("Circuit breaker CLOSED after successful probe");
            }
        } else if (current == State.CLOSED) {
            failureCount.set(0);
        }
    }

    /** Records a failed call. */
    void recordFailure() {
        State current = state.get();
        if (current == State.HALF_OPEN) {
            // Publish openedAt before the state CAS so any thread observing OPEN sees a fresh
            // cooldown anchor (avoids admitting a request against a stale openedAt).
            openedAt.set(System.currentTimeMillis());
            if (state.compareAndSet(State.HALF_OPEN, State.OPEN)) {
                probeInFlight.set(false);
                LOG.warning("Circuit breaker re-OPENED after failed probe");
            }
        } else if (current == State.CLOSED) {
            int count = failureCount.incrementAndGet();
            if (count >= failureThreshold) {
                // Like the HALF_OPEN branch, openedAt is published before the state CAS so a thread
                // that observes OPEN never reads a stale cooldown anchor. This is deliberately
                // asymmetric with recordSuccess(), which mutates only after winning its CAS: a lost
                // CAS here leaves a harmless openedAt≈now write, whereas a premature CLOSED would
                // wrongly admit traffic.
                openedAt.set(System.currentTimeMillis());
                if (state.compareAndSet(State.CLOSED, State.OPEN)) {
                    failureCount.set(0);
                    LOG.warning(
                            () ->
                                    "Circuit breaker OPENED after "
                                            + count
                                            + " consecutive failures");
                }
            }
        }
    }

    State state() {
        return state.get();
    }

    int failureCount() {
        return failureCount.get();
    }
}
