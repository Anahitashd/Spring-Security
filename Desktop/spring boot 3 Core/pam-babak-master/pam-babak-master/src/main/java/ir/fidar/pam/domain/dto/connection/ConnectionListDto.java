package ir.fidar.pam.domain.dto.connection;

import ir.fidar.core.domain.dto.crud.FullAuditionReadDto;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.FileTransferMode;

public class ConnectionListDto extends FullAuditionReadDto {
   private ConnectionType type;
   private String name;
   private String ipAddress;
   private int port;
   private FileTransferMode fileTransferMode;
   private Boolean clipboard;

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

   public FileTransferMode getFileTransferMode() {
      return this.fileTransferMode;
   }

   public void setFileTransferMode(FileTransferMode fileTransferMode) {
      this.fileTransferMode = fileTransferMode;
   }

   public Boolean getClipboard() {
      return this.clipboard;
   }

   public void setClipboard(Boolean clipboard) {
      this.clipboard = clipboard;
   }
}
