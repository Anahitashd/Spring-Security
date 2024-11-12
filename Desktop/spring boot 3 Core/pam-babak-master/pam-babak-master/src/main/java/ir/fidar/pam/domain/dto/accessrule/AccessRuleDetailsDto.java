package ir.fidar.pam.domain.dto.accessrule;

import ir.fidar.core.domain.dto.crud.FullAuditionDescriptiveDetailsDto;
import ir.fidar.core.domain.dto.management.user.UserInfoDto;
import ir.fidar.core.domain.dto.management.usergroup.UserGroupInfoDto;
import ir.fidar.pam.domain.dto.BannerDetailsDto;
import ir.fidar.pam.domain.dto.SessionInputConstraintViolationHandlerDetailsDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.AccessibilityTimePeriodConstraintDetailsDto;
import ir.fidar.pam.domain.dto.bridge.BridgeInfoDto;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupInfoDto;
import ir.fidar.pam.domain.type.FileTransferMode;
import java.util.List;
import java.util.Set;

public class AccessRuleDetailsDto extends FullAuditionDescriptiveDetailsDto {
   private String name;
   private Set<AccessRuleConnectionReadDto> connections;
   private Set<ConnectionGroupInfoDto> connectionGroups;
   private BridgeInfoDto bridge;
   private List<UserInfoDto> users;
   private List<UserGroupInfoDto> userGroups;
   private boolean disabled;
   private long expirationTime;
   private boolean clipboard;
   private boolean bastion;
   private FileTransferMode fileTransferMode = FileTransferMode.NONE;
   private List<BannerDetailsDto> banners;
   private boolean ocrEnabled;
   private List<SessionInputConstraintViolationHandlerDetailsDto> sessionInputConstraints;
   private AccessibilityTimePeriodConstraintDetailsDto accessibilityTimePeriodConstraint;
   private boolean captureDisabled;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public Set<AccessRuleConnectionReadDto> getConnections() {
      return this.connections;
   }

   public void setConnections(Set<AccessRuleConnectionReadDto> connections) {
      this.connections = connections;
   }

   public Set<ConnectionGroupInfoDto> getConnectionGroups() {
      return this.connectionGroups;
   }

   public void setConnectionGroups(Set<ConnectionGroupInfoDto> connectionGroups) {
      this.connectionGroups = connectionGroups;
   }

   public BridgeInfoDto getBridge() {
      return this.bridge;
   }

   public void setBridge(BridgeInfoDto bridge) {
      this.bridge = bridge;
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

   public boolean isDisabled() {
      return this.disabled;
   }

   public void setDisabled(boolean disabled) {
      this.disabled = disabled;
   }

   public long getExpirationTime() {
      return this.expirationTime;
   }

   public void setExpirationTime(long expirationTime) {
      this.expirationTime = expirationTime;
   }

   public boolean isClipboard() {
      return this.clipboard;
   }

   public void setClipboard(boolean clipboard) {
      this.clipboard = clipboard;
   }

   public boolean isBastion() {
      return this.bastion;
   }

   public void setBastion(boolean bastion) {
      this.bastion = bastion;
   }

   public FileTransferMode getFileTransferMode() {
      return this.fileTransferMode;
   }

   public void setFileTransferMode(FileTransferMode fileTransferMode) {
      this.fileTransferMode = fileTransferMode;
   }

   public List<BannerDetailsDto> getBanners() {
      return this.banners;
   }

   public void setBanners(List<BannerDetailsDto> banners) {
      this.banners = banners;
   }

   public boolean isOcrEnabled() {
      return this.ocrEnabled;
   }

   public void setOcrEnabled(boolean ocrEnabled) {
      this.ocrEnabled = ocrEnabled;
   }

   public List<SessionInputConstraintViolationHandlerDetailsDto> getSessionInputConstraints() {
      return this.sessionInputConstraints;
   }

   public void setSessionInputConstraints(List<SessionInputConstraintViolationHandlerDetailsDto> sessionInputConstraints) {
      this.sessionInputConstraints = sessionInputConstraints;
   }

   public AccessibilityTimePeriodConstraintDetailsDto getAccessibilityTimePeriodConstraint() {
      return this.accessibilityTimePeriodConstraint;
   }

   public void setAccessibilityTimePeriodConstraint(AccessibilityTimePeriodConstraintDetailsDto accessibilityTimePeriodConstraint) {
      this.accessibilityTimePeriodConstraint = accessibilityTimePeriodConstraint;
   }

   public boolean isCaptureDisabled() {
      return this.captureDisabled;
   }

   public void setCaptureDisabled(boolean captureDisabled) {
      this.captureDisabled = captureDisabled;
   }
}
