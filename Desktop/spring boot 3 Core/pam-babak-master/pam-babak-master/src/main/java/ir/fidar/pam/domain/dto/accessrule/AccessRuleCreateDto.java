package ir.fidar.pam.domain.dto.accessrule;

import ir.fidar.core.domain.dto.crud.AbstractDescriptiveCreateDto;
import ir.fidar.core.domain.util.constraint.InFuture;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.dto.BannerCreateDto;
import ir.fidar.pam.domain.dto.SessionInputConstraintViolationHandlerCreateDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.AccessibilityTimePeriodConstraintCreateDto;
import ir.fidar.pam.domain.type.FileTransferMode;
import ir.fidar.pam.domain.util.constraint.SessionInputConstraintUniqueRegexInList;
import java.util.List;
import java.util.Set;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class AccessRuleCreateDto extends AbstractDescriptiveCreateDto {
   @ValidName
   @Size(
      max = 48,
      message = "gt_max.name"
   )
   @XssProtected
   private String name;
   private Set<String> connections;
   private Set<String> connectionGroups;
   private Set<ConnectionSpecialSetting> connectionSpecialSettings;
   @NotBlank(
      message = "blank.bridge"
   )
   private String bridge;
   private Set<String> users;
   private Set<String> userGroups;
   private boolean disabled;
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
   private boolean clipboard;
   private boolean bastion;
   private FileTransferMode fileTransferMode = FileTransferMode.NONE;
   private List<BannerCreateDto> banners;
   private boolean ocrEnabled;
   @SessionInputConstraintUniqueRegexInList(
      message = "dup_regex.sessionInputConstraints"
   )
   private List<SessionInputConstraintViolationHandlerCreateDto> sessionInputConstraints;
   @Valid
   private AccessibilityTimePeriodConstraintCreateDto accessibilityTimePeriodConstraint;
   private boolean captureDisabled;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public Set<String> getConnections() {
      return this.connections;
   }

   public void setConnections(Set<String> connections) {
      this.connections = connections;
   }

   public Set<String> getConnectionGroups() {
      return this.connectionGroups;
   }

   public void setConnectionGroups(Set<String> connectionGroups) {
      this.connectionGroups = connectionGroups;
   }

   public Set<ConnectionSpecialSetting> getConnectionSpecialSettings() {
      return this.connectionSpecialSettings;
   }

   public void setConnectionSpecialSettings(Set<ConnectionSpecialSetting> connectionSpecialSettings) {
      this.connectionSpecialSettings = connectionSpecialSettings;
   }

   public String getBridge() {
      return this.bridge;
   }

   public void setBridge(String bridge) {
      this.bridge = bridge;
   }

   public Set<String> getUsers() {
      return this.users;
   }

   public void setUsers(Set<String> users) {
      this.users = users;
   }

   public Set<String> getUserGroups() {
      return this.userGroups;
   }

   public void setUserGroups(Set<String> userGroups) {
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

   public List<BannerCreateDto> getBanners() {
      return this.banners;
   }

   public void setBanners(List<BannerCreateDto> banners) {
      this.banners = banners;
   }

   public boolean isOcrEnabled() {
      return this.ocrEnabled;
   }

   public void setOcrEnabled(boolean ocrEnabled) {
      this.ocrEnabled = ocrEnabled;
   }

   public List<SessionInputConstraintViolationHandlerCreateDto> getSessionInputConstraints() {
      return this.sessionInputConstraints;
   }

   public void setSessionInputConstraints(List<SessionInputConstraintViolationHandlerCreateDto> sessionInputConstraints) {
      this.sessionInputConstraints = sessionInputConstraints;
   }

   public AccessibilityTimePeriodConstraintCreateDto getAccessibilityTimePeriodConstraint() {
      return this.accessibilityTimePeriodConstraint;
   }

   public void setAccessibilityTimePeriodConstraint(AccessibilityTimePeriodConstraintCreateDto accessibilityTimePeriodConstraint) {
      this.accessibilityTimePeriodConstraint = accessibilityTimePeriodConstraint;
   }

   public boolean isCaptureDisabled() {
      return this.captureDisabled;
   }

   public void setCaptureDisabled(boolean captureDisabled) {
      this.captureDisabled = captureDisabled;
   }
}
