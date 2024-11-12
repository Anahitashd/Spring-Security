package ir.fidar.pam.domain.dto.report.useractivity;

import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.SessionTransferFileMode;
import ir.fidar.pam.domain.type.SessionTransferredFileStatus;

public class UserTransferredFilesOverRemoteSessionDto {
   private String connectionName;
   private String connectionIpAddress;
   private ConnectionType connectionType;
   private String fileName;
   private long time;
   private SessionTransferFileMode mode;
   private SessionTransferredFileStatus status;

   public String getConnectionName() {
      return this.connectionName;
   }

   public void setConnectionName(String connectionName) {
      this.connectionName = connectionName;
   }

   public String getConnectionIpAddress() {
      return this.connectionIpAddress;
   }

   public void setConnectionIpAddress(String connectionIpAddress) {
      this.connectionIpAddress = connectionIpAddress;
   }

   public ConnectionType getConnectionType() {
      return this.connectionType;
   }

   public void setConnectionType(ConnectionType connectionType) {
      this.connectionType = connectionType;
   }

   public String getFileName() {
      return this.fileName;
   }

   public void setFileName(String fileName) {
      this.fileName = fileName;
   }

   public long getTime() {
      return this.time;
   }

   public void setTime(long time) {
      this.time = time;
   }

   public SessionTransferFileMode getMode() {
      return this.mode;
   }

   public void setMode(SessionTransferFileMode mode) {
      this.mode = mode;
   }

   public SessionTransferredFileStatus getStatus() {
      return this.status;
   }

   public void setStatus(SessionTransferredFileStatus status) {
      this.status = status;
   }
}
