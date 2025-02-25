package ir.fidar.pam.management;

import ir.fidar.core.domain.util.constraint.ValidIp;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(
   prefix = "converter"
)
@Component
public class ConverterHostProperties {
   @ValidIp
   private String ipAddress;
   private int port;

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
}
