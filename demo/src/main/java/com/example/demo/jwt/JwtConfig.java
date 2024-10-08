package com.example.demo.jwt;

import io.jsonwebtoken.security.Keys;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;

import javax.crypto.SecretKey;
import java.net.http.HttpHeaders;

@ConfigurationProperties(prefix = "application.jwt")
public class JwtConfig {

    private String secretKeys;
    private String tokenPrefix;
    private Integer tokenExpirationAfterDays;

    public JwtConfig(){
    }

    public String getSecretKeys() {
        return secretKeys;
    }
    public void setSecretKeys(String secretKeys) {
        this.secretKeys = secretKeys;
    }
    public String getTokenPrefix() {
        return tokenPrefix;
    }
    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }
    public Integer getTokenExpirationAfterDays() {
        return tokenExpirationAfterDays;
    }
    public void setTokenExpirationAfterDays(Integer tokenExpirationAfterDays) {
        this.tokenExpirationAfterDays = tokenExpirationAfterDays;
    }



    public String getAuthorizationHeader() {
        return HttpHeaders.AUTHORIZATION;
    }
}
