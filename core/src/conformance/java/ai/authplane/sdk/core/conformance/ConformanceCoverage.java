package ai.authplane.sdk.core.conformance;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Describes how closely a concrete test matches the shared conformance catalog case. */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface ConformanceCoverage {
    ConformanceCoverageLevel level() default ConformanceCoverageLevel.FULL;

    String[] gaps() default {};

    String note() default "";
}
