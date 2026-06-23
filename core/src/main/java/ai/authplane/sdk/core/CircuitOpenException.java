package ai.authplane.sdk.core;

/**
 * Thrown by {@link CircuitBreaker#execute} when a call is not admitted — the breaker is OPEN within
 * its cooldown, or a HALF_OPEN probe is already in flight. The wrapped AS operation is never
 * invoked.
 *
 * <p>Package-private — internal control-flow signal between {@link CircuitBreaker} and {@link
 * AuthplaneClient}, which translates it into the public AS-call exception type.
 */
final class CircuitOpenException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    CircuitOpenException() {
        super("Circuit breaker is open; AS calls temporarily suspended");
    }
}
