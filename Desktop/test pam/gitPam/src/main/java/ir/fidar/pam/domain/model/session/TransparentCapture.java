package ir.fidar.pam.domain.model.session;

import ir.fidar.core.domain.model.BaseEntity;
import ir.fidar.core.domain.util.constraint.ValidIp;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.pam.domain.type.CaptureStatus;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.util.converter.attribbute.CaptureStatusConverter;
import ir.fidar.pam.domain.util.converter.attribbute.connection.ConnectionTypeConverter;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(
   name = "tb_transparent_capture"
)
public class TransparentCapture extends BaseEntity {
   @NotBlank(
      message = "blank.uuid"
   )
   @Size(
      max = 48,
      message = "gt_max.uuid"
   )
   private String sessionId;
   @NotNull(
      message = "null.status"
   )
   @Convert(
      converter = CaptureStatusConverter.class
   )
   private CaptureStatus status;
   @Min(
      value = 1L,
      message = "lt_min.startTime"
   )
   private long startTime;
   @Min(
      value = 0L,
      message = "lt_min.endTime"
   )
   private long endTime;
   @NotNull(
      message = "null.type"
   )
   @Convert(
      converter = ConnectionTypeConverter.class
   )
   private ConnectionType connectionType;
   @ValidName
   private String connectionName;
   @NotBlank(
      message = "blank.connectionIpAddress"
   )
   @ValidIp
   private String connectionIpAddress;
   @Min(
      value = 1L,
      message = "lt_min.connectionPort"
   )
   @Max(
      value = 65535L,
      message = "gt_max.connectionPort"
   )
   private int connectionPort;
   @NotBlank(
      message = "blank.clientIpAddress"
   )
   @ValidIp
   private String clientIpAddress;
   @Min(
      value = 1L,
      message = "lt_min.connectionPort"
   )
   @Max(
      value = 65535L,
      message = "gt_max.connectionPort"
   )
   private Integer clientPort;
   @Size(
      max = 64,
      message = "gt_max.clientUsername"
   )
   private String clientUsername;
   @Size(
      max = 128,
      message = "gt_max.clientPassword"
   )
   private String clientPassword;
   @Size(
      max = 64,
      message = "gt_max.clientDomain"
   )
   private String clientDomain;
   @Size(
      max = 64,
      message = "gt_max.clientHostname"
   )
   private String clientHostname;
   @Size(
      max = 64,
      message = "gt_max.certificateName"
   )
   private String clientCertificateName;

   public String getSessionId() {
      return this.sessionId;
   }

   public void setSessionId(String uuid) {
      this.sessionId = uuid;
   }

   public CaptureStatus getStatus() {
      return this.status;
   }

   public void setStatus(CaptureStatus status) {
      this.status = status;
   }

   public long getStartTime() {
      return this.startTime;
   }

   public void setStartTime(long startTime) {
      this.startTime = startTime;
   }

   public long getEndTime() {
      return this.endTime;
   }

   public void setEndTime(long endTime) {
      this.endTime = endTime;
   }

   public ConnectionType getConnectionType() {
      return this.connectionType;
   }

   public void setConnectionType(ConnectionType type) {
      this.connectionType = type;
   }

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

   public int getConnectionPort() {
      return this.connectionPort;
   }

   public void setConnectionPort(int connectionPort) {
      this.connectionPort = connectionPort;
   }

   public String getClientIpAddress() {
      return this.clientIpAddress;
   }

   public void setClientIpAddress(String clientIpAddress) {
      this.clientIpAddress = clientIpAddress;
   }

   public Integer getClientPort() {
      return this.clientPort;
   }

   public void setClientPort(Integer clientPort) {
      this.clientPort = clientPort;
   }

   public String getClientUsername() {
      return this.clientUsername;
   }

   public void setClientUsername(String clientUsername) {
      this.clientUsername = clientUsername;
   }

   public String getClientPassword() {
      return this.clientPassword;
   }

   public void setClientPassword(String clientPassword) {
      this.clientPassword = clientPassword;
   }

   public String getClientDomain() {
      return this.clientDomain;
   }

   public void setClientDomain(String clientDomain) {
      this.clientDomain = clientDomain;
   }

   public String getClientHostname() {
      return this.clientHostname;
   }

   public void setClientHostname(String clientHostName) {
      this.clientHostname = clientHostName;
   }

   public String getClientCertificateName() {
      return this.clientCertificateName;
   }

   public void setClientCertificateName(String credentialName) {
      this.clientCertificateName = credentialName;
   }
}
