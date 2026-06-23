package ai.authplane.sdk.core.conformance;

public enum ConformanceCoverageLevel {
    FULL("full"),
    PARTIAL("partial");

    private final String wireValue;

    ConformanceCoverageLevel(String wireValue) {
        this.wireValue = wireValue;
    }

    String wireValue() {
        return wireValue;
    }
}
