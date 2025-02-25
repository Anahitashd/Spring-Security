package ir.fidar.pam.domain.dto.connectionaccessrequest;

import ir.fidar.core.domain.dto.crud.AbstractDescriptiveCreateDto;
import ir.fidar.core.domain.util.constraint.ValidIp;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.FileTransferMode;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

public class ConnectionAccessRequestCreateDto extends AbstractDescriptiveCreateDto {
   @NotBlank(
      message = "blank.ipAddress"
   )
   @ValidIp
   @XssProtected
   private String ipAddress;
   @Min(
      value = 1L,
      message = "lt_min.port"
   )
   @Max(
      value = 65535L,
      message = "gt_max.port"
   )
   private int port;
   @NotNull(
      message = "null.type"
   )
   private ConnectionType type;
   private boolean clipboardEnabled;
   @NotNull(
      message = "null.fileTransferMode"
   )
   private FileTransferMode fileTransferMode;

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
}
