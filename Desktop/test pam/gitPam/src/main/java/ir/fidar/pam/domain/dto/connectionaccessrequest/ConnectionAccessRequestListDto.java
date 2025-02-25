package ir.fidar.pam.domain.dto.connectionaccessrequest;

import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.pam.domain.type.ConnectionAccessRequestStatus;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.FileTransferMode;

public class ConnectionAccessRequestListDto implements ListDto {
   private String identifier;
   private long applicationTime;
   private String ipAddress;
   private int port;
   private ConnectionType type;
   private boolean clipboardEnabled;
   private FileTransferMode fileTransferMode;
   private ConnectionAccessRequestStatus status;

   public String getIdentifier() {
      return this.identifier;
   }

   public void setIdentifier(String identifier) {
      this.identifier = identifier;
   }

   public long getApplicationTime() {
      return this.applicationTime;
   }

   public void setApplicationTime(long applicationTime) {
      this.applicationTime = applicationTime;
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

   public boolean isClipboardEnabled() {
      return this.clipboardEnabled;
   }

   public void setClipboardEnabled(boolean clipboardEnabled) {
      this.clipboardEnabled = clipboardEnabled;
   }

   public FileTransferMode getFileTransferMode() {
      return this.fileTransferMode;
   }

   public void setFileTransferMode(FileTransferMode fileTransferMode) {
      this.fileTransferMode = fileTransferMode;
   }

   public ConnectionAccessRequestStatus getStatus() {
      return this.status;
   }

   public void setStatus(ConnectionAccessRequestStatus status) {
      this.status = status;
   }
}
