package ai.authplane.sdk.spring.security.demo;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Component;

import ai.authplane.sdk.spring.security.AuthplaneAuthentication;

@Component
public class MathTools {

  @Tool(description = "Adds two integers and returns the result")
  public int add(int a, int b) {
    AuthplaneAuthentication.current().requireScope("tools/add");
    return a + b;
  }

  @Tool(description = "Multiplies two integers and returns the result")
  public int multiply(int a, int b) {
    AuthplaneAuthentication.current().requireScope("tools/multiply");
    return a * b;
  }
}
