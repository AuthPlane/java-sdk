# authplane-sdk

[![Maven Central](https://img.shields.io/maven-central/v/ai.authplane.sdk/authplane-sdk?style=flat-square&label=authplane-sdk)](https://central.sonatype.com/artifact/ai.authplane.sdk/authplane-sdk)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../LICENSE)

Framework-agnostic OAuth 2.1 JWT validation and token operations for Java resource servers.

## Install

```xml
<dependency>
    <groupId>ai.authplane.sdk</groupId>
    <artifactId>authplane-sdk</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

Requires Java 21+.

## Quickstart

```java
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.VerifiedClaims;

import java.util.List;

try (AuthplaneClient client =
        AuthplaneClient.builder("https://auth.example.com").build().get()) {

    AuthplaneResource verifier =
            client.resource("https://api.example.com", List.of("read:data", "write:data"));

    VerifiedClaims claims = verifier.verify(bearerToken).get().claims();
    claims.requireScope("read:data");

    String subject = claims.sub();
}
```

Call `client.close()` on shutdown to clear the token cache. Background refreshes run on daemon threads and need no explicit shutdown.

## Documentation

Full API reference, configuration options, DPoP, token operations, introspection, token exchange, error hierarchy, and advanced usage: **[User Guide](docs/user-guide.md)**.
