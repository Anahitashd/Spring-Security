package ir.fidar.pam.domain.dto.bridge;

import ir.fidar.core.domain.dto.crud.FullAuditionDescriptiveDetailsDto;

public class BridgeDetailsDto extends FullAuditionDescriptiveDetailsDto {
   private String name;
   private String ipAddress;
   private int port;
   private String recordsStoragePath;
   private String rdpVirtualDriveStoragePath;

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

   public String getRecordsStoragePath() {
      return this.recordsStoragePath;
   }

   public void setRecordsStoragePath(String recordsStoragePath) {
      this.recordsStoragePath = recordsStoragePath;
   }

   public String getRdpVirtualDriveStoragePath() {
      return this.rdpVirtualDriveStoragePath;
   }

   public void setRdpVirtualDriveStoragePath(String rdpVirtualDriveStoragePath) {
      this.rdpVirtualDriveStoragePath = rdpVirtualDriveStoragePath;
   }
}
