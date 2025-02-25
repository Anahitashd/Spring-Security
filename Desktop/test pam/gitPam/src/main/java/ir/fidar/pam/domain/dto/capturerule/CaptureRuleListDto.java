package ir.fidar.pam.domain.dto.capturerule;

import ir.fidar.core.domain.dto.crud.FullAuditionReadDto;

public class CaptureRuleListDto extends FullAuditionReadDto {
   private String name;
   private int numberOfConnections;
   private int numberOfUsers;
   private boolean export;
   private boolean keystroke;
   private long expirationTime;
   private boolean disabled;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public int getNumberOfConnections() {
      return this.numberOfConnections;
   }

   public void setNumberOfConnections(int numberOfConnections) {
      this.numberOfConnections = numberOfConnections;
   }

   public int getNumberOfUsers() {
      return this.numberOfUsers;
   }

   public void setNumberOfUsers(int numberOfUsers) {
      this.numberOfUsers = numberOfUsers;
   }

   public boolean isExport() {
      return this.export;
   }

   public void setExport(boolean export) {
      this.export = export;
   }

   public boolean isKeystroke() {
      return this.keystroke;
   }

   public void setKeystroke(boolean keystroke) {
      this.keystroke = keystroke;
   }

   public long getExpirationTime() {
      return this.expirationTime;
   }

   public void setExpirationTime(long expirationTime) {
      this.expirationTime = expirationTime;
   }

   public boolean isDisabled() {
      return this.disabled;
   }

   public void setDisabled(boolean disabled) {
      this.disabled = disabled;
   }
}
