package ir.fidar.pam.domain.model;

import ir.fidar.core.domain.model.FullAuditionDescriptiveBaseEntity;
import ir.fidar.core.domain.util.constraint.ReachableHost;
import ir.fidar.core.domain.util.constraint.ValidIp;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.management.log.crud.EnableAutoCrudLogging;
import ir.fidar.core.security.authorization.model.CrudRequest;
import ir.fidar.core.security.authorization.model.annotations.CrudPrivilege;
import ir.fidar.core.security.authorization.model.annotations.Secure;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.dto.bridge.BridgeCreateDto;
import ir.fidar.pam.domain.dto.bridge.BridgeUpdateDto;
import ir.fidar.pam.service.impl.BridgeCrudServiceImpl;
import java.util.Objects;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Secure(
   section = "BRIDGE",
   crud = @CrudPrivilege(
      baseURLs = {"/api/bridges/*"},
      requests = {CrudRequest.ALL}
   )
)
@EnableAutoCrudLogging(
   displayName = "Bridge",
   crudServiceImpl = BridgeCrudServiceImpl.class,
   createDto = BridgeCreateDto.class,
   updateDto = BridgeUpdateDto.class,
   uniquePropertyName = "Name"
)
@Entity
@Table(
   name = "tb_bridge"
)
@ReachableHost(
   message = "unreachable_host",
   ipAddressProperty = "ipAddress",
   portProperty = "port",
   targetClass = Bridge.class
)
public class Bridge extends FullAuditionDescriptiveBaseEntity {
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

   public void setIpAddress(String host) {
      this.ipAddress = host;
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

   public void setRecordsStoragePath(String recordingPath) {
      this.recordsStoragePath = recordingPath;
   }

   public String getRdpVirtualDriveStoragePath() {
      return this.rdpVirtualDriveStoragePath;
   }

   public void setRdpVirtualDriveStoragePath(String fileTransferPath) {
      this.rdpVirtualDriveStoragePath = fileTransferPath;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (o != null && this.getClass() == o.getClass()) {
         Bridge bridge = (Bridge)o;
         return this.name.equals(bridge.name);
      } else {
         return false;
      }
   }

   @Override
   public int hashCode() {
      return Objects.hash(this.name);
   }
}
