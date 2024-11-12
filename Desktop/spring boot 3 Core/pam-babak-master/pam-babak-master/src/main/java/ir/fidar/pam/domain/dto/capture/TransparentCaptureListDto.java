package ir.fidar.pam.domain.dto.capture;

import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.pam.domain.type.CaptureStatus;
import ir.fidar.pam.domain.type.ConnectionType;

public class TransparentCaptureListDto implements ListDto {
   private String sessionId;
   private CaptureStatus status;
   private long startTime;
   private long endTime;
   private ConnectionType connectionType;
   private String connectionName;
   private String connectionIpAddress;
   private Integer connectionPort;
   private String clientIpAddress;
   private Integer clientPort;
   private String clientUsername;
   private String clientPassword;
   private String clientDomain;
   private String clientHostname;
   private String clientCertificateName;
   private long videoSize;

   public String getSessionId() {
      return this.sessionId;
   }

   public void setSessionId(String sessionId) {
      this.sessionId = sessionId;
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

   public void setConnectionType(ConnectionType connectionType) {
      this.connectionType = connectionType;
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

   public Integer getConnectionPort() {
      return this.connectionPort;
   }

   public void setConnectionPort(Integer connectionPort) {
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

   public void setClientHostname(String clientHostname) {
      this.clientHostname = clientHostname;
   }

   public String getClientCertificateName() {
      return this.clientCertificateName;
   }

   public void setClientCertificateName(String clientCertificateName) {
      this.clientCertificateName = clientCertificateName;
   }

   public long getVideoSize() {
      return this.videoSize;
   }

   public void setVideoSize(long videoSize) {
      this.videoSize = videoSize;
   }
}
