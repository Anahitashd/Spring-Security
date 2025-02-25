package ir.fidar.pam.config;

import ir.fidar.core.security.authorization.initialization.properties.SecurityProperties;
import ir.fidar.core.security.context.HttpSecurityConfigurer;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer.AuthorizedUrl;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.cors.CorsConfiguration;

@Component
public class HttpSecurityConfiguration implements HttpSecurityConfigurer {
   private static final Map<String, Set<String>> CSRF_IGNORING_URLS_PER_METHOD = new HashMap<>();
   private final AntPathMatcher antPathMatcher;
   private final SecurityProperties securityProperties;

   public HttpSecurityConfiguration(SecurityProperties securityProperties) {
      this.securityProperties = securityProperties;
      this.antPathMatcher = new AntPathMatcher();
   }

   @Override
   public void configure(HttpSecurity httpSecurity) throws Exception {
      ((AuthorizedUrl)((AuthorizedUrl)((AuthorizedUrl)((AuthorizedUrl)((AuthorizedUrl)((AuthorizedUrl)((AuthorizedUrl)((AuthorizedUrl)((AuthorizedUrl)httpSecurity.authorizeRequests(
                                       
                                    )
                                    .antMatchers(new String[]{"/api/remote-session/**"}))
                                 .permitAll()
                                 .antMatchers(HttpMethod.POST, new String[]{"/api/transparent-captures"}))
                              .permitAll()
                              .antMatchers(HttpMethod.GET, new String[]{"/api/transparent-captures/connection-port-mapping/*"}))
                           .permitAll()
                           .antMatchers(HttpMethod.PUT, new String[]{"/api/transparent-captures/*/close"}))
                        .permitAll()
                        .antMatchers(HttpMethod.GET, new String[]{"/api/transparent-captures/*/play-video"}))
                     .permitAll()
                     .antMatchers(new String[]{"/api/connection-access-requests/*/review"}))
                  .hasRole("SUPERUSER")
                  .antMatchers(new String[]{"/api/batch-command-execution"}))
               .hasRole("SUPERUSER")
               .antMatchers(new String[]{"/api/management/excel-ie"}))
            .hasRole("SUPERUSER")
            .antMatchers(new String[]{"/api/reports/user-activity/*"}))
         .hasRole("SUPERUSER");
      if (this.securityProperties.isEnableCsrf()) {
         httpSecurity.csrf().ignoringRequestMatchers(new RequestMatcher[]{httpServletRequest -> {
            String method = httpServletRequest.getMethod();
            String uri = httpServletRequest.getRequestURI();
            Set<String> pattern = CSRF_IGNORING_URLS_PER_METHOD.get(method.toLowerCase());
            return pattern != null && pattern.stream().anyMatch(p -> this.antPathMatcher.match(p, uri));
         }});
      } else {
         httpSecurity.csrf().disable();
      }

      httpSecurity.cors()
         .configurationSource(
            httpServletRequest -> {
               String method = httpServletRequest.getMethod();
               String uri = httpServletRequest.getRequestURI();
               boolean optionMethod = method.equalsIgnoreCase("options");
               Set<String> patterns = CSRF_IGNORING_URLS_PER_METHOD.get(method.toLowerCase());
               if (patterns != null || optionMethod) {
                  if (patterns == null) {
                     patterns = CSRF_IGNORING_URLS_PER_METHOD.values().stream().flatMap(Collection::stream).collect(Collectors.toSet());
                  }
      
                  String pattern = patterns.stream().filter(p -> this.antPathMatcher.match(p, uri)).findAny().orElse(null);
                  if (pattern != null) {
                     if (optionMethod) {
                        method = CSRF_IGNORING_URLS_PER_METHOD.keySet()
                           .stream()
                           .filter(key -> CSRF_IGNORING_URLS_PER_METHOD.get(key).stream().anyMatch(p -> p.equalsIgnoreCase(pattern)))
                           .findAny()
                           .orElse(null);
                     }
      
                     if (method != null) {
                        CorsConfiguration corsConfiguration = new CorsConfiguration();
                        corsConfiguration.setAllowedMethods(Collections.singletonList("*"));
                        corsConfiguration.setAllowedOrigins(Collections.singletonList("*"));
                        corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));
                        return corsConfiguration;
                     }
                  }
               }
      
               return null;
            }
         );
   }

   static {
      CSRF_IGNORING_URLS_PER_METHOD.put("get", Stream.of("/api/transparent-captures/connection-port-mapping/*").collect(Collectors.toSet()));
      CSRF_IGNORING_URLS_PER_METHOD.put("post", Stream.of("/api/transparent-captures").collect(Collectors.toSet()));
      CSRF_IGNORING_URLS_PER_METHOD.put("put", Stream.of("/api/transparent-captures/*/close").collect(Collectors.toSet()));
   }
}
