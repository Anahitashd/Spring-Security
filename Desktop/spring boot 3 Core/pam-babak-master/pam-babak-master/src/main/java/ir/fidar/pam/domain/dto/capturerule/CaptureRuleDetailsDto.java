package ir.fidar.pam.domain.dto.capturerule;

import ir.fidar.core.domain.dto.crud.FullAuditionDescriptiveDetailsDto;
import ir.fidar.core.domain.dto.management.user.UserInfoDto;
import ir.fidar.core.domain.dto.management.usergroup.UserGroupInfoDto;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupInfoDto;
import ir.fidar.pam.domain.dto.connection.ConnectionInfoDto;
import java.util.List;

public class CaptureRuleDetailsDto extends FullAuditionDescriptiveDetailsDto {
   private String name;
   private List<ConnectionInfoDto> connections;
   private List<ConnectionGroupInfoDto> connectionGroups;
   private List<UserInfoDto> users;
   private List<UserGroupInfoDto> userGroups;
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

   public List<ConnectionInfoDto> getConnections() {
      return this.connections;
   }

   public void setConnections(List<ConnectionInfoDto> connections) {
      this.connections = connections;
   }

   public List<ConnectionGroupInfoDto> getConnectionGroups() {
      return this.connectionGroups;
   }

   public void setConnectionGroups(List<ConnectionGroupInfoDto> connectionGroups) {
      this.connectionGroups = connectionGroups;
   }

   public List<UserInfoDto> getUsers() {
      return this.users;
   }

   public void setUsers(List<UserInfoDto> users) {
      this.users = users;
   }

   public List<UserGroupInfoDto> getUserGroups() {
      return this.userGroups;
   }

   public void setUserGroups(List<UserGroupInfoDto> userGroups) {
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
