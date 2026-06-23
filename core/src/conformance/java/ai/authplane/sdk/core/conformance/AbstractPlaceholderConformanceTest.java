package ai.authplane.sdk.core.conformance;

import static org.junit.jupiter.api.Assertions.fail;

abstract class AbstractPlaceholderConformanceTest {

    protected final void notImplemented(String caseId) {
        fail("Not implemented: " + caseId);
    }
}
