package ir.fidar.pam.domain.dto.report.useractivity;

import ir.fidar.pam.domain.type.ConnectionType;

public class UserRemoteSessionDurationDto {
   private String ipAddress;
   private ConnectionType connectionType;
   private long startTime;
   private long duration;

   public String getIpAddress() {
      return this.ipAddress;
   }

   public void setIpAddress(String ipAddress) {
      this.ipAddress = ipAddress;
   }

   public ConnectionType getConnectionType() {
      return this.connectionType;
   }

   public void setConnectionType(ConnectionType connectionType) {
      this.connectionType = connectionType;
   }

   public long getStartTime() {
      return this.startTime;
   }

   public void setStartTime(long startTime) {
      this.startTime = startTime;
   }

   public long getDuration() {
      return this.duration;
   }

   public void setDuration(long duration) {
      this.duration = duration;
   }
}
