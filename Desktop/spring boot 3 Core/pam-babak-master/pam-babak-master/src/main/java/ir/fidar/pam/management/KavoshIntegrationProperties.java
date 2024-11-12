package ir.fidar.pam.management;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(
   prefix = "kavosh"
)
@Component
public class KavoshIntegrationProperties {
   private String host;
   private int port;
   private boolean https;
   private String token;
   private String baseUrl;
   private int intervalTimeout;
   private int maxResultWait;
   private KavoshIntegrationProperties.SpeedMode speedMode;
   private String tempStorage;

   public String getHost() {
      return this.host;
   }

   public void setHost(String host) {
      this.host = host;
   }

   public int getPort() {
      return this.port;
   }

   public void setPort(int port) {
      this.port = port;
   }

   public boolean isHttps() {
      return this.https;
   }

   public void setHttps(boolean https) {
      this.https = https;
   }

   public String getToken() {
      return this.token;
   }

   public void setToken(String token) {
      this.token = token;
   }

   public String getBaseUrl() {
      return this.baseUrl;
   }

   public void setBaseUrl(String baseUrl) {
      this.baseUrl = baseUrl;
   }

   public int getIntervalTimeout() {
      return this.intervalTimeout;
   }

   public void setIntervalTimeout(int intervalTimeout) {
      this.intervalTimeout = intervalTimeout;
   }

   public int getMaxResultWait() {
      return this.maxResultWait;
   }

   public void setMaxResultWait(int maxResultWait) {
      this.maxResultWait = maxResultWait;
   }

   public KavoshIntegrationProperties.SpeedMode getSpeedMode() {
      return this.speedMode;
   }

   public void setSpeedMode(KavoshIntegrationProperties.SpeedMode speedMode) {
      this.speedMode = speedMode;
   }

   public String getTempStorage() {
      return this.tempStorage;
   }

   public void setTempStorage(String tempStorage) {
      this.tempStorage = tempStorage;
   }

   public static enum SpeedMode {
      ALL,
      ULTRA,
      FAST,
      MEDIUM,
      SLOW;
   }
}
