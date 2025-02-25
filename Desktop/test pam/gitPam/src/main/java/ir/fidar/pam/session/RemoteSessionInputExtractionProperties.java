package ir.fidar.pam.session;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(
   prefix = "remote-session-input-extraction"
)
@Component
public class RemoteSessionInputExtractionProperties {
   private int maxPoolSize;
   private String threadNamePrefix;

   public int getMaxPoolSize() {
      return this.maxPoolSize;
   }

   public void setMaxPoolSize(int maxPoolSize) {
      this.maxPoolSize = maxPoolSize;
   }

   public String getThreadNamePrefix() {
      return this.threadNamePrefix;
   }

   public void setThreadNamePrefix(String threadNamePrefix) {
      this.threadNamePrefix = threadNamePrefix;
   }
}
