package ai.authplane.sdk.core.errors;

import java.io.Serial;

/**
 * Thrown when a token exchange fails because the user has not yet granted consent for the requested
 * service. Carries an optional {@code consentUrl} that callers can surface to the user (e.g. via
 * MCP URL elicitation) to drive the consent flow.
 */
public final class ConsentRequiredException extends TokenExchangeException {

    @Serial private static final long serialVersionUID = 1L;

    private final String serviceId;
    private final String causeDetail;
    private final String consentUrl; // nullable

    /**
     * @param message human-readable message
     * @param oauthError OAuth error code (e.g. {@code consent_required}, {@code
     *     interaction_required})
     * @param serviceId identifier of the downstream service requiring consent
     * @param causeDetail extra detail explaining why consent is needed
     * @param consentUrl URL the user should visit to grant consent; may be {@code null}
     */
    public ConsentRequiredException(
            String message,
            String oauthError,
            String serviceId,
            String causeDetail,
            String consentUrl) {
        super(message, oauthError);
        this.serviceId = serviceId;
        this.causeDetail = causeDetail;
        this.consentUrl = consentUrl;
    }

    public String serviceId() {
        return serviceId;
    }

    public String causeDetail() {
        return causeDetail;
    }

    public String consentUrl() {
        return consentUrl;
    }
}
