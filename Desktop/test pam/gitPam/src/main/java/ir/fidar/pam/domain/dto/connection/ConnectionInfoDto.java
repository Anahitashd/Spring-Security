package ir.fidar.pam.domain.dto.connection;

import ir.fidar.core.domain.dto.crud.InfoDto;
import ir.fidar.pam.domain.type.ConnectionType;

public class ConnectionInfoDto implements InfoDto {
   private ConnectionType type;
   private String name;
   private String ipAddress;
   private int port;

   public ConnectionType getType() {
      return this.type;
   }

   public void setType(ConnectionType type) {
      this.type = type;
   }

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

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
