package ir.fidar.pam.domain.dto.capture;

import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.pam.domain.type.CaptureStatus;
import ir.fidar.pam.domain.type.ConnectionType;

public class CaptureListDto implements ListDto {
   private String sessionId;
   private CaptureStatus status;
   private long startTime;
   private long endTime;
   private ConnectionType type;
   private String owner;
   private String connectionName;
   private String connectionIpAddress;
   private String bridgeName;
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

   public ConnectionType getType() {
      return this.type;
   }

   public void setType(ConnectionType type) {
      this.type = type;
   }

   public String getOwner() {
      return this.owner;
   }

   public void setOwner(String owner) {
      this.owner = owner;
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

   public String getBridgeName() {
      return this.bridgeName;
   }

   public void setBridgeName(String bridgeName) {
      this.bridgeName = bridgeName;
   }

   public long getVideoSize() {
      return this.videoSize;
   }

   public void setVideoSize(long videoSize) {
      this.videoSize = videoSize;
   }
}
