package ai.authplane.sdk.core.conformance;

enum ConformanceStatus {
    PASSED("passed"),
    FAILED("failed"),
    SKIPPED("skipped"),
    NOT_RUN("not_run");

    private final String wireValue;

    ConformanceStatus(String wireValue) {
        this.wireValue = wireValue;
    }

    String wireValue() {
        return wireValue;
    }
}
