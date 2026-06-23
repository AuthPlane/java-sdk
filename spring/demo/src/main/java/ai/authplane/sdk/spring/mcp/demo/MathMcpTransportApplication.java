package ai.authplane.sdk.spring.mcp.demo;

import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.AuthProvider;
import ai.authplane.sdk.spring.mcp.AuthplaneMcpServerConfig;

/**
 * Transport-profile demo: JWT validation at the MCP transport layer, no Spring Security.
 *
 * <p>Run with: {@code mvn spring-boot:run -Ptransport}
 *
 * <p>{@link AuthplaneMcpServerConfig} wires the Authplane verifier directly into the MCP transport's
 * security hooks ({@code securityValidator} / {@code contextExtractor}). Spring Security
 * auto-configuration is excluded — there is no filter chain. Scope enforcement in tools uses {@code
 * AuthplaneMcpServerAdapter.getClaims(...).requireScope(...)}.
 */
@SpringBootApplication(
    exclude = {
      SecurityAutoConfiguration.class,
      OAuth2ResourceServerAutoConfiguration.class,
      ServletWebSecurityAutoConfiguration.class
    })
@Import(AuthplaneMcpServerConfig.class)
public class MathMcpTransportApplication {

  public static void main(String[] args) {
    SpringApplication.run(MathMcpTransportApplication.class, args);
  }

  @Bean
  public ToolCallbackProvider mathTransportToolCallbacks(MathTransportTools mathTransportTools) {
    return MethodToolCallbackProvider.builder().toolObjects(mathTransportTools).build();
  }

  /**
   * Supplies static client credentials for introspection / token exchange. The SDK reads
   * credentials only from an {@link AuthProvider} bean, so this maps the {@code CLIENT_ID} /
   * {@code CLIENT_SECRET} environment variables to {@link ASCredentials}. Registered only when
   * {@code CLIENT_ID} is set.
   */
  @Bean
  @ConditionalOnProperty("CLIENT_ID")
  public AuthProvider authProvider(
      @Value("${CLIENT_ID}") String clientId, @Value("${CLIENT_SECRET:}") String clientSecret) {
    return new ASCredentials(clientId, clientSecret);
  }
}
