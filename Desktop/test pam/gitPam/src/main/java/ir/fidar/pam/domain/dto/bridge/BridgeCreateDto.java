package ir.fidar.pam.domain.dto.bridge;

import ir.fidar.core.domain.dto.crud.AbstractDescriptiveCreateDto;
import ir.fidar.core.domain.util.constraint.ReachableHost;
import ir.fidar.core.domain.util.constraint.ValidIp;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.security.validation.XssProtected;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@ReachableHost(
   message = "unreachable_host",
   ipAddressProperty = "ipAddress",
   portProperty = "port",
   targetClass = BridgeCreateDto.class
)
public class BridgeCreateDto extends AbstractDescriptiveCreateDto {
   @ValidName
   @Size(
      max = 48,
      message = "gt_max.name"
   )
   @XssProtected
   private String name;
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
   @NotBlank(
      message = "blank.recordingPath"
   )
   private String recordsStoragePath;
   @NotBlank(
      message = "null.fileTransferPath"
   )
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
