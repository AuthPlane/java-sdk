package ai.authplane.sdk.core.oauth;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.util.JSONObjectUtils;

import ai.authplane.sdk.core.AuthProvider;
import ai.authplane.sdk.core.dpop.DPoPProvider;
import ai.authplane.sdk.core.fetching.HttpTransport;
import ai.authplane.sdk.core.fetching.RawPostResponse;

final class OAuthPostSupport {

    private OAuthPostSupport() {}

    static RawPostResponse postForm(
            String url,
            Map<String, String> formData,
            AuthProvider authProvider,
            HttpTransport transport,
            DPoPProvider dpopProvider)
            throws Exception {
        return postForm(
                url,
                formData == null ? List.of() : new ArrayList<>(formData.entrySet()),
                authProvider,
                transport,
                dpopProvider);
    }

    static RawPostResponse postForm(
            String url,
            List<Map.Entry<String, String>> formData,
            AuthProvider authProvider,
            HttpTransport transport,
            DPoPProvider dpopProvider)
            throws Exception {

        // Resolve auth headers once per request so a DPoP nonce retry reuses the same credentials.
        Map<String, String> authHeaders = authProvider == null ? null : authProvider.authHeaders();

        RawPostResponse response =
                transport.postRaw(url, formData, buildHeaders(authHeaders, dpopProvider, url));

        if (dpopProvider == null) {
            return response;
        }

        String nonce = response.header("dpop-nonce");
        if (nonce != null && !nonce.isBlank()) {
            dpopProvider.noteNonce(url, nonce);
        }

        // RFC 9449 §6.1: retry exactly once with the server-issued nonce.
        // A second use_dpop_nonce response is not retried — we return it as-is.
        if (response.statusCode() == 400 && nonce != null && isUseNonceError(response)) {
            RawPostResponse retryResponse =
                    transport.postRaw(url, formData, buildHeaders(authHeaders, dpopProvider, url));
            String retryNonce = retryResponse.header("dpop-nonce");
            if (retryNonce != null && !retryNonce.isBlank()) {
                dpopProvider.noteNonce(url, retryNonce);
            }
            return retryResponse;
        }

        return response;
    }

    static void requireSuccessStatus(RawPostResponse response, String url) throws IOException {
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException(
                    "OAuth POST failed: HTTP " + response.statusCode() + " from " + url);
        }
    }

    private static Map<String, String> buildHeaders(
            Map<String, String> authHeaders, DPoPProvider dpopProvider, String url) {

        Map<String, String> headers = new LinkedHashMap<>();
        if (authHeaders != null) {
            headers.putAll(authHeaders);
        }
        if (dpopProvider != null) {
            headers.putAll(dpopProvider.buildHeaders("POST", url));
        }
        return headers.isEmpty() ? null : headers;
    }

    private static boolean isUseNonceError(RawPostResponse response) {
        try {
            Map<String, Object> body = JSONObjectUtils.parse(response.body());
            return "use_dpop_nonce".equals(body.get("error"));
        } catch (Exception e) {
            return false;
        }
    }
}
