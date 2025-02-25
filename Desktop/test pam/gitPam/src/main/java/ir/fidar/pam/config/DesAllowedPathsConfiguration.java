package ir.fidar.pam.config;

import ir.fidar.core.security.authorization.model.HttpMethod;
import ir.fidar.core.security.context.AllowedPath;
import ir.fidar.core.security.context.AllowedPathsRegistry;
import ir.fidar.core.security.context.DesAllowedPathsConfigurer;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.stereotype.Component;

@Component
public class DesAllowedPathsConfiguration implements DesAllowedPathsConfigurer {
   @Override
   public void registerAllowedPath(AllowedPathsRegistry registry) {
      registry.add(
         new AllowedPath("/api/remote-session/*", Stream.of(HttpMethod.GET).collect(Collectors.toSet())),
         new AllowedPath("/api/remote-session/*/*", Stream.of(HttpMethod.GET).collect(Collectors.toSet())),
         new AllowedPath("/api/sessions/*", Stream.of(HttpMethod.GET).collect(Collectors.toSet())),
         new AllowedPath("/api/sessions/*/terminate", Stream.of(HttpMethod.GET).collect(Collectors.toSet())),
         new AllowedPath("/api/sessions/*/download-stream", Stream.of(HttpMethod.GET).collect(Collectors.toSet())),
         new AllowedPath("/api/sessions/*/upload-stream", Stream.of(HttpMethod.POST).collect(Collectors.toSet())),
         new AllowedPath("/api/transparent-captures", Stream.of(HttpMethod.POST).collect(Collectors.toSet())),
         new AllowedPath("/api/transparent-captures/*/close", Stream.of(HttpMethod.PUT).collect(Collectors.toSet())),
         new AllowedPath("/api/transparent-captures/*/play-video", Stream.of(HttpMethod.GET).collect(Collectors.toSet())),
         new AllowedPath("/api/transparent-captures/connection-port-mapping/*", Stream.of(HttpMethod.GET).collect(Collectors.toSet())),
         new AllowedPath("/api/sessions/*/requested-files/*", Stream.of(HttpMethod.GET).collect(Collectors.toSet())),
         new AllowedPath("/api/access-rules/connection-info/*", Stream.of(HttpMethod.GET).collect(Collectors.toSet())),
         new AllowedPath("/api/reporting/charts/*", Stream.of(HttpMethod.GET).collect(Collectors.toSet())),
         new AllowedPath(
            "/api/resource-access-info/*", Stream.of(HttpMethod.GET, HttpMethod.DELETE, HttpMethod.PUT, HttpMethod.POST).collect(Collectors.toSet())
         ),
         new AllowedPath(
            "/api/connection-access-requests/*", Stream.of(HttpMethod.GET, HttpMethod.DELETE, HttpMethod.PUT, HttpMethod.POST).collect(Collectors.toSet())
         ),
         new AllowedPath("/api/connection-access-requests/*/review", Stream.of(HttpMethod.PUT).collect(Collectors.toSet())),
         new AllowedPath("/api/batch-command-execution", Stream.of(HttpMethod.POST).collect(Collectors.toSet())),
         new AllowedPath("/api/management/excel-ie/*", Stream.of(HttpMethod.POST, HttpMethod.GET).collect(Collectors.toSet())),
         new AllowedPath("/api/reports/user-activity/*", Stream.of(HttpMethod.GET).collect(Collectors.toSet()))
      );
   }
}
