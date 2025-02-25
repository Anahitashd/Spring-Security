package ir.fidar.pam.domain.dto.bridge;

import ir.fidar.core.domain.dto.crud.FullAuditionReadDto;

public class BridgeListDto extends FullAuditionReadDto {
   private String name;
   private String ipAddress;
   private int port;

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
