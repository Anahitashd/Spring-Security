package com.example.demo.config;


import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.security.SecuritySchemes;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(title = "APIs", version = "v1"),
        security = {
                @SecurityRequirement(name = "apiKeyAuth"),
                @SecurityRequirement(name = "httpAuth"),
                @SecurityRequirement(name = "bearerAuth"),
        })
@SecuritySchemes({
        @SecurityScheme(
                name = "apiKeyAuth",
                type = SecuritySchemeType.APIKEY,
                in = SecuritySchemeIn.HEADER,
                paramName = "Authorization"
        ),
        @SecurityScheme(
                name = "bearerAuth",
                type = SecuritySchemeType.HTTP,
                scheme = "bearer",
                bearerFormat = "JWT"
        ),
        @SecurityScheme(
                name = "httpAuth",
                type = SecuritySchemeType.HTTP,
                scheme = "basic"
        ),

})
public class OpenApiConfig {
}
