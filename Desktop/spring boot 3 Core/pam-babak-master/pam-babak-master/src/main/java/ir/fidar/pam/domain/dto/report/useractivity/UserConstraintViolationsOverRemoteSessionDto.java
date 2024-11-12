package ir.fidar.pam.domain.dto.report.useractivity;

import ir.fidar.pam.domain.type.ConnectionType;

public class UserConstraintViolationsOverRemoteSessionDto {
   private String connectionName;
   private String connectionIpAddress;
   private ConnectionType connectionType;
   private String input;
   private String regex;
   private long time;

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

   public String getInput() {
      return this.input;
   }

   public void setInput(String input) {
      this.input = input;
   }

   public String getRegex() {
      return this.regex;
   }

   public void setRegex(String regex) {
      this.regex = regex;
   }

   public long getTime() {
      return this.time;
   }

   public void setTime(long time) {
      this.time = time;
   }
}
