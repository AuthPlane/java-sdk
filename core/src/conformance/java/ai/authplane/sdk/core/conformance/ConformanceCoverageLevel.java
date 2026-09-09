package ai.authplane.sdk.core.conformance;

public enum ConformanceCoverageLevel {
    FULL("full"),
    PARTIAL("partial"),
    /**
     * No part of the case is exercised. Distinct from {@link #PARTIAL}: the catalog's report
     * contract uses the level to tell a consciously deferred case apart from one that is partly
     * covered, so a case whose behaviour is absent altogether must not report as partial.
     */
    NONE("none");

    private final String wireValue;

    ConformanceCoverageLevel(String wireValue) {
        this.wireValue = wireValue;
    }

    String wireValue() {
        return wireValue;
    }
}
