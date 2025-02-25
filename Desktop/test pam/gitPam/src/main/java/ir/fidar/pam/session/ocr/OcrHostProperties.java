package ir.fidar.pam.session.ocr;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(
   prefix = "ocr"
)
@Component
public class OcrHostProperties {
   private String host;
   private int port;
   private String storagePath;
   private String batchCommandPath;

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

   public String getStoragePath() {
      return this.storagePath;
   }

   public void setStoragePath(String storagePath) {
      this.storagePath = storagePath;
   }

   public String getBatchCommandPath() {
      return this.batchCommandPath;
   }

   public void setBatchCommandPath(String batchCommandPath) {
      this.batchCommandPath = batchCommandPath;
   }
}
