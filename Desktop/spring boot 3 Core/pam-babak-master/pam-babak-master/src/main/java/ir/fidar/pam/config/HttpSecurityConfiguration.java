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
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.cors.CorsConfiguration;

import javax.servlet.http.HttpServletRequest;

@Component
public class HttpSecurityConfiguration implements HttpSecurityConfigurer {
    private static final Map<String, Set<String>> CSRF_IGNORING_URLS_PER_METHOD = new HashMap<>();
    private final AntPathMatcher antPathMatcher;
    private final SecurityProperties securityProperties;
    private HttpServletRequest request;

    public HttpSecurityConfiguration(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
        this.antPathMatcher = new AntPathMatcher();
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests((requests) -> requests
                .requestMatchers(new String[]{"/api/remote-session/**"})
                .permitAll()
                .requestMatchers(HttpMethod.POST, new String[]{"/api/transparent-captures"})
                .permitAll()
                .requestMatchers(HttpMethod.GET, new String[]{"/api/transparent-captures/connection-port-mapping/*"})
                .permitAll()
                .requestMatchers(HttpMethod.PUT, new String[]{"/api/transparent-captures/*/close"})
                .permitAll()
                .requestMatchers(HttpMethod.GET, new String[]{"/api/transparent-captures/*/play-video"})
                .permitAll()
                .requestMatchers(new String[]{"/api/connection-access-requests/*/review"})
                .hasRole("SUPERUSER")
                .requestMatchers(new String[]{"/api/batch-command-execution"})
                .hasRole("SUPERUSER")
                .requestMatchers(new String[]{"/api/management/excel-ie"})
                .hasRole("SUPERUSER")
                .requestMatchers(new String[]{"/api/reports/user-activity/*"})
                .hasRole("SUPERUSER"));
        if (this.securityProperties.isEnableCsrf()) {
            httpSecurity
                    .csrf(csrf -> csrf.ignoringRequestMatchers(new RequestMatcher() {
                        @Override
                        public boolean matches(jakarta.servlet.http.HttpServletRequest request) {
                            String method = request.getMethod();
                            String uri = request.getRequestURI();
                            Set<String> patterns = CSRF_IGNORING_URLS_PER_METHOD.get(method.toLowerCase());
                            return patterns != null && patterns.stream().anyMatch(pattern -> antPathMatcher.match(pattern, uri));
                        }

                    }));
        } else {
            httpSecurity.csrf(AbstractHttpConfigurer::disable);
        }

        httpSecurity.cors(c -> c
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
                ));
    }

    static {
        CSRF_IGNORING_URLS_PER_METHOD.put("get", Stream.of("/api/transparent-captures/connection-port-mapping/*").collect(Collectors.toSet()));
        CSRF_IGNORING_URLS_PER_METHOD.put("post", Stream.of("/api/transparent-captures").collect(Collectors.toSet()));
        CSRF_IGNORING_URLS_PER_METHOD.put("put", Stream.of("/api/transparent-captures/*/close").collect(Collectors.toSet()));
    }
}
