package ir.fidar.pam.domain.dto;

import ir.fidar.pam.domain.dto.connection.ConnectionInfoDto;

public class SessionDto {
   private String uuid;
   private String name;
   private boolean clipboard;
   private ConnectionInfoDto connection;

   public String getUuid() {
      return this.uuid;
   }

   public void setUuid(String uuid) {
      this.uuid = uuid;
   }

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public boolean isClipboard() {
      return this.clipboard;
   }

   public void setClipboard(boolean clipboard) {
      this.clipboard = clipboard;
   }

   public ConnectionInfoDto getConnection() {
      return this.connection;
   }

   public void setConnection(ConnectionInfoDto connection) {
      this.connection = connection;
   }
}
