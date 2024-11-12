package ir.fidar.pam.domain.dto.capturerule;

import ir.fidar.core.domain.dto.crud.AbstractDescriptiveCreateDto;
import ir.fidar.core.domain.util.constraint.InFuture;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.security.validation.XssProtected;
import java.util.List;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;

public class CaptureRuleCreateDto extends AbstractDescriptiveCreateDto {
   @ValidName
   @Size(
      max = 48,
      message = "gt_max.name"
   )
   @XssProtected
   private String name;
   private List<String> connections;
   private List<String> connectionGroups;
   private List<String> users;
   private List<String> userGroups;
   private boolean export;
   private boolean keystroke;
   @Min(
      value = 0L,
      message = "lt_min.expirationTime"
   )
   @Max(
      value = 4000000000L,
      message = "gt_max.expirationTime"
   )
   @InFuture(
      message = "in_past.expirationTime"
   )
   private long expirationTime;
   private boolean disabled;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public List<String> getConnections() {
      return this.connections;
   }

   public void setConnections(List<String> connections) {
      this.connections = connections;
   }

   public List<String> getConnectionGroups() {
      return this.connectionGroups;
   }

   public void setConnectionGroups(List<String> connectionGroups) {
      this.connectionGroups = connectionGroups;
   }

   public List<String> getUsers() {
      return this.users;
   }

   public void setUsers(List<String> users) {
      this.users = users;
   }

   public List<String> getUserGroups() {
      return this.userGroups;
   }

   public void setUserGroups(List<String> userGroups) {
      this.userGroups = userGroups;
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
