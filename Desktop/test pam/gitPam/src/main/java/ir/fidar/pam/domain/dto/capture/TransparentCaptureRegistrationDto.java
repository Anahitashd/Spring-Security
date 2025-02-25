package ir.fidar.pam.domain.dto.capture;

import ir.fidar.core.domain.util.constraint.ValidIp;
import ir.fidar.pam.domain.type.ConnectionType;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class TransparentCaptureRegistrationDto {
   @NotBlank(
      message = "blank.connectionIpAddress"
   )
   @ValidIp
   private String connectionIpAddress;
   @NotNull(
      message = "null.connectionPort"
   )
   @Min(
      value = 1L,
      message = "lt_min.connectionPort"
   )
   @Max(
      value = 65535L,
      message = "gt_max.connectionPort"
   )
   private Integer connectionPort;
   @NotNull(
      message = "null.connectionType"
   )
   private ConnectionType connectionType;
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
      max = 128,
      message = "gt_max.username"
   )
   private String clientUsername;
   @Size(
      max = 128,
      message = "gt_max.password"
   )
   private String clientPassword;
   @Size(
      max = 255,
      message = "gt_max.domain"
   )
   private String clientDomain;
   @Size(
      max = 128,
      message = "gt_max.clientHostname"
   )
   private String clientHostname;
   @Size(
      max = 255,
      message = "gt_max.certificateName"
   )
   private String clientCertificateName;

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

   public ConnectionType getConnectionType() {
      return this.connectionType;
   }

   public void setConnectionType(ConnectionType connectionType) {
      this.connectionType = connectionType;
   }

   public String getClientIpAddress() {
      return this.clientIpAddress;
   }

   public void setClientIpAddress(String clientIpAddress) {
      this.clientIpAddress = clientIpAddress;
   }

   public int getClientPort() {
      return this.clientPort;
   }

   public void setClientPort(int clientPort) {
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

   public void setClientHostname(String clientHostname) {
      this.clientHostname = clientHostname;
   }

   public String getClientCertificateName() {
      return this.clientCertificateName;
   }

   public void setClientCertificateName(String clientCertificateName) {
      this.clientCertificateName = clientCertificateName;
   }
}
