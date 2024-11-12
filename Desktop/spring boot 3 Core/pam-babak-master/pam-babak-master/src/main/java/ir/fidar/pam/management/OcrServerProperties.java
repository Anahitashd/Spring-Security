package ir.fidar.pam.management;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(
   prefix = "ocr-server"
)
@Component
public class OcrServerProperties {
   private String ipAddress;
   private int port;
   private String requestUrl;

   public String getIpAddress() {
      return this.ipAddress;
   }

   public void setIpAddress(String ipAddress) {
      this.ipAddress = ipAddress;
   }

   public int getPort() {
      return this.port;
   }

   public void setPort(int port) {
      this.port = port;
   }

   public String getRequestUrl() {
      return this.requestUrl;
   }

   public void setRequestUrl(String requestUrl) {
      this.requestUrl = requestUrl;
   }
}
