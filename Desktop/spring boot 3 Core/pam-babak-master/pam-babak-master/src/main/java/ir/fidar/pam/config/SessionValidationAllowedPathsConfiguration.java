package ir.fidar.pam.config;

import ir.fidar.core.security.authorization.model.HttpMethod;
import ir.fidar.core.security.context.AllowedPath;
import ir.fidar.core.security.context.AllowedPathsRegistry;
import ir.fidar.core.security.context.SessionValidationAllowedPathsConfigurer;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.stereotype.Component;

@Component
public class SessionValidationAllowedPathsConfiguration implements SessionValidationAllowedPathsConfigurer {
   @Override
   public void registerAllowedPath(AllowedPathsRegistry registry) throws Exception {
      registry.add(
         new AllowedPath("/api/remote-session/*", Stream.of(HttpMethod.GET).collect(Collectors.toSet())),
         new AllowedPath("/api/remote-session/*/*", Stream.of(HttpMethod.GET).collect(Collectors.toSet())),
         new AllowedPath("/api/transparent-captures", Stream.of(HttpMethod.POST).collect(Collectors.toSet())),
         new AllowedPath("/api/transparent-captures/*/close", Stream.of(HttpMethod.PUT).collect(Collectors.toSet())),
         new AllowedPath("/api/transparent-captures/*/play-video", Stream.of(HttpMethod.GET).collect(Collectors.toSet())),
         new AllowedPath("/api/transparent-captures/connection-port-mapping/*", Stream.of(HttpMethod.GET).collect(Collectors.toSet()))
      );
   }
}
