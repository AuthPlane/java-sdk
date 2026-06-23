package ai.authplane.sdk.spring.security.demo;

import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.AuthProvider;
import ai.authplane.sdk.spring.security.AuthplaneSecurityConfig;

/**
 * Security-profile demo: JWT validation via Spring Security filter chain.
 *
 * <p>Run with: {@code mvn spring-boot:run -Psecurity}
 *
 * <p>The {@link AuthplaneSecurityConfig} sets up a Spring Security filter chain that
 * extracts and validates Bearer tokens before requests reach the MCP transport. Scope enforcement
 * in tools uses {@code AuthplaneAuthentication.current().requireScope(...)}.
 */
@SpringBootApplication
@Import(AuthplaneSecurityConfig.class)
public class MathMcpServerApplication {

  public static void main(String[] args) {
    SpringApplication.run(MathMcpServerApplication.class, args);
  }

  @Bean
  public ToolCallbackProvider mathToolCallbacks(MathTools mathTools) {
    return MethodToolCallbackProvider.builder().toolObjects(mathTools).build();
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
