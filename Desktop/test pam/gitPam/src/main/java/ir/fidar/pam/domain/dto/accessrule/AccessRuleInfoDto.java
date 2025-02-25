package ir.fidar.pam.domain.dto.accessrule;

import ir.fidar.core.domain.dto.crud.InfoDto;
import ir.fidar.pam.domain.type.ConnectionType;

public class AccessRuleInfoDto implements InfoDto {
   private String name;
   private String connectionName;
   private String ipAddress;
   private int port;
   private ConnectionType type;
   private boolean clipboard;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public String getConnectionName() {
      return this.connectionName;
   }

   public void setConnectionName(String connectionName) {
      this.connectionName = connectionName;
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

   public ConnectionType getType() {
      return this.type;
   }

   public void setType(ConnectionType type) {
      this.type = type;
   }

   public boolean isClipboard() {
      return this.clipboard;
   }

   public void setClipboard(boolean clipboard) {
      this.clipboard = clipboard;
   }
}
