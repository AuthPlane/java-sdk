package ai.authplane.sdk.core.conformance;

import java.util.Optional;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;

public final class ConformanceExtension implements TestWatcher {

    private static final ExtensionContext.Namespace NAMESPACE =
            ExtensionContext.Namespace.create(ConformanceExtension.class);
    private static final String STATE_KEY = "conformance-run-state";

    @Override
    public void testSuccessful(ExtensionContext context) {
        record(context, ConformanceStatus.PASSED, null);
    }

    @Override
    public void testFailed(ExtensionContext context, Throwable cause) {
        record(context, ConformanceStatus.FAILED, cause);
    }

    @Override
    public void testAborted(ExtensionContext context, Throwable cause) {
        record(context, ConformanceStatus.SKIPPED, cause);
    }

    @Override
    public void testDisabled(ExtensionContext context, Optional<String> reason) {
        record(
                context,
                ConformanceStatus.SKIPPED,
                reason.filter(value -> !value.isBlank())
                        .map(IllegalStateException::new)
                        .orElse(null));
    }

    private static void record(
            ExtensionContext context, ConformanceStatus status, Throwable failure) {
        ConformanceRunState state =
                context.getRoot()
                        .getStore(NAMESPACE)
                        .getOrComputeIfAbsent(
                                STATE_KEY,
                                ignored -> ConformanceRunState.createDefault(),
                                ConformanceRunState.class);

        String testId = ConformanceRunState.testId(context);
        ConformanceCase mapping =
                context.getRequiredTestMethod().getAnnotation(ConformanceCase.class);
        ConformanceCoverage coverage =
                context.getRequiredTestMethod().getAnnotation(ConformanceCoverage.class);
        if (mapping == null) {
            state.recordUncatalogued(testId, status, failure);
            return;
        }

        state.recordMapped(mapping.value(), testId, status, failure, coverage);
    }
}
