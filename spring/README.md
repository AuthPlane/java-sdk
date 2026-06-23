# authplane-spring

[![Maven Central](https://img.shields.io/maven-central/v/ai.authplane.sdk/authplane-spring?style=flat-square&label=authplane-spring)](https://central.sonatype.com/artifact/ai.authplane.sdk/authplane-spring)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](../LICENSE)

Authplane JWT authentication for [Spring Boot](https://spring.io/projects/spring-boot) MCP servers. Integrates with Spring Security's OAuth2 resource server filter chain, or with Spring AI's MCP WebMVC transport directly.

## Install

```xml
<dependency>
  <groupId>ai.authplane.sdk</groupId>
  <artifactId>authplane-spring</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>

<!-- Required for the Spring Security integration path -->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

Requires Java 21+ and Spring Boot 4.x.

## Quickstart

```java
import ai.authplane.sdk.spring.security.AuthplaneAuthentication;
import ai.authplane.sdk.spring.security.AuthplaneSecurityConfig;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;
import org.springframework.stereotype.Component;

@SpringBootApplication
@Import(AuthplaneSecurityConfig.class)
public class MyMcpServer {
    public static void main(String[] args) {
        SpringApplication.run(MyMcpServer.class, args);
    }
}

@Component
class MyTools {
    @Tool(description = "Execute a query")
    public String query(String sql) {
        AuthplaneAuthentication.current().requireScope("tools/query");
        return runQuery(sql);
    }
}
```

```properties
authplane.issuer=https://auth.company.com
authplane.resource=https://mcp.company.com/mcp
authplane.scopes=tools/query,tools/write
```

## Documentation

Configuration reference, the Spring Security vs transport-hooks paths, scope enforcement, PRM behaviour, token revocation, token exchange, error handling, manual bean wiring, and the full API: **[User Guide](docs/user-guide.md)**.
