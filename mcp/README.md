# authplane-mcp

[![Maven Central](https://img.shields.io/maven-central/v/ai.authplane.sdk/authplane-mcp?style=flat-square&label=authplane-mcp)](https://central.sonatype.com/artifact/ai.authplane.sdk/authplane-mcp)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](../LICENSE)

Authplane JWT authentication for servers built on the [MCP Java SDK](https://github.com/modelcontextprotocol/java-sdk). No Spring required.

## Install

```xml
<dependency>
  <groupId>ai.authplane.sdk</groupId>
  <artifactId>authplane-mcp</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
```

The MCP Java SDK and `jakarta.servlet-api` are `provided` — include them in your application's own dependencies. Requires Java 21+.

## Quickstart

```java
AuthplaneMcpSetup setup = AuthplaneMcpSetup.builder()
        .issuer("https://auth.example.com")
        .resource("https://mcp.example.com/mcp")
        .scopes(List.of("tools/query", "tools/write"))
        .build()
        .get();

HttpServletStreamableServerTransportProvider transport =
        HttpServletStreamableServerTransportProvider.builder()
                .mcpEndpoint(setup.mcpPath())
                .securityValidator(setup.adapter())
                .contextExtractor(setup.adapter())
                .build();

McpServer.sync(transport)
        .serverInfo(Implementation.builder("MyServer", "1.0.0").build())
        .tools(/* ... */)
        .build();

setup.registerServlets(servletContext, transport);
```

Call `setup.client().close()` on shutdown to clear the token cache.

## Documentation

Configuration reference, scope enforcement, PRM behaviour, token revocation, token exchange + URL elicitation, error handling, manual setup, and the full API: **[User Guide](docs/user-guide.md)**.
