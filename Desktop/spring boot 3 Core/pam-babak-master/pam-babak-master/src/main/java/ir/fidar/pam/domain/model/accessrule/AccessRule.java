package ir.fidar.pam.domain.model.accessrule;

import ir.fidar.core.domain.model.FullAuditionDescriptiveBaseEntity;
import ir.fidar.core.domain.util.constraint.InFuture;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.management.log.crud.EnableAutoCrudLogging;
import ir.fidar.core.security.authorization.model.CrudRequest;
import ir.fidar.core.security.authorization.model.annotations.CrudPrivilege;
import ir.fidar.core.security.authorization.model.annotations.Dependency;
import ir.fidar.core.security.authorization.model.annotations.DependencyList;
import ir.fidar.core.security.authorization.model.annotations.Secure;
import ir.fidar.core.security.authorization.model.annotations.Source;
import ir.fidar.core.security.authorization.model.annotations.Target;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.dto.accessrule.AccessRuleCreateDto;
import ir.fidar.pam.domain.dto.accessrule.AccessRuleUpdateDto;
import ir.fidar.pam.domain.model.Banner;
import ir.fidar.pam.domain.model.Bridge;
import ir.fidar.pam.domain.model.SessionInputConstraintViolationHandler;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.AccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.connection.ConnectionGroup;
import ir.fidar.pam.domain.model.management.User;
import ir.fidar.pam.domain.model.management.UserGroup;
import ir.fidar.pam.domain.type.FileTransferMode;
import ir.fidar.pam.domain.util.converter.attribbute.FileTransferModeConverter;
import ir.fidar.pam.service.impl.AccessRuleCrudServiceImpl;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Secure(
   section = "ACCESS_RULE",
   crud = @CrudPrivilege(
      baseURLs = {"/api/access-rules/*", "/api/management/users/*/access-rules", "/api/management/user-groups/*/access-rules", "/api/connections/*/access-rules", "/api/connection-groups/*/access-rules"},
      requests = {CrudRequest.ALL}
   ),
   dependencies = @DependencyList({@Dependency(
         source = @Source(
            cruds = {CrudRequest.CREATE, CrudRequest.UPDATE}
         ),
         target = @Target(
            section = "CONNECTION",
            cruds = {CrudRequest.READ}
         )
      ), @Dependency(
         source = @Source(
            cruds = {CrudRequest.CREATE, CrudRequest.UPDATE}
         ),
         target = @Target(
            section = "USER",
            cruds = {CrudRequest.READ}
         )
      ), @Dependency(
         source = @Source(
            cruds = {CrudRequest.CREATE, CrudRequest.UPDATE}
         ),
         target = @Target(
            section = "BRIDGE",
            cruds = {CrudRequest.READ}
         )
      ), @Dependency(
         source = @Source(
            cruds = {CrudRequest.CREATE, CrudRequest.UPDATE}
         ),
         target = @Target(
            section = "SESSION_INPUT_CONSTRAINT",
            cruds = {CrudRequest.READ}
         )
      )})
)
@EnableAutoCrudLogging(
   displayName = "Access Rule",
   crudServiceImpl = AccessRuleCrudServiceImpl.class,
   createDto = AccessRuleCreateDto.class,
   updateDto = AccessRuleUpdateDto.class,
   uniquePropertyName = "Name"
)
@Entity
@Table(
   name = "tb_access_rule"
)
public class AccessRule extends FullAuditionDescriptiveBaseEntity {
   @NotBlank(
      message = "blank.uuid"
   )
   private String uuid;
   @ValidName
   @Size(
      max = 48,
      message = "gt_max.name"
   )
   @XssProtected
   private String name;
   @OneToMany(
      fetch = FetchType.LAZY,
      mappedBy = "accessRule",
      cascade = {CascadeType.ALL},
      orphanRemoval = true
   )
   private Set<AccessRuleConnection> connections = new HashSet<>();
   @ManyToMany(
      fetch = FetchType.LAZY,
      cascade = {CascadeType.PERSIST, CascadeType.MERGE}
   )
   @JoinTable(
      name = "tb_access_rule_connection_group",
      joinColumns = {@JoinColumn(
         name = "access_rule_id"
      )},
      inverseJoinColumns = {@JoinColumn(
         name = "connection_group_id"
      )}
   )
   private Set<ConnectionGroup> connectionGroups = new HashSet<>();
   @NotNull(
      message = "null.bridge"
   )
   @OneToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "bridge_id"
   )
   private Bridge bridge;
   @ManyToMany(
      fetch = FetchType.LAZY,
      cascade = {CascadeType.PERSIST, CascadeType.MERGE}
   )
   @JoinTable(
      name = "tb_access_rule_user",
      joinColumns = {@JoinColumn(
         name = "access_rule_id"
      )},
      inverseJoinColumns = {@JoinColumn(
         name = "user_id"
      )}
   )
   private Set<User> users = new HashSet<>();
   @ManyToMany(
      fetch = FetchType.LAZY,
      cascade = {CascadeType.PERSIST, CascadeType.MERGE}
   )
   @JoinTable(
      name = "tb_access_rule_user_group",
      joinColumns = {@JoinColumn(
         name = "access_rule_id"
      )},
      inverseJoinColumns = {@JoinColumn(
         name = "user_group_id"
      )}
   )
   private Set<UserGroup> userGroups = new HashSet<>();
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
   @NotNull(
      message = "null.fileTransferMode"
   )
   @Convert(
      converter = FileTransferModeConverter.class
   )
   private FileTransferMode fileTransferMode;
   private boolean clipboard;
   private boolean bastion;
   @OneToMany(
      fetch = FetchType.LAZY,
      cascade = {CascadeType.ALL},
      mappedBy = "accessRule"
   )
   private Set<Banner> banners = new HashSet<>();
   private boolean ocrEnabled;
   @OneToMany(
      fetch = FetchType.LAZY,
      cascade = {CascadeType.ALL},
      mappedBy = "accessRule"
   )
   private Set<SessionInputConstraintViolationHandler> sessionInputConstraints;
   @OneToOne(
      fetch = FetchType.LAZY,
      cascade = {CascadeType.ALL},
      mappedBy = "accessRule"
   )
   private AccessibilityTimePeriodConstraint accessibilityTimePeriodConstraint;
   private boolean captureDisabled;

   public String getUuid() {
      return this.uuid;
   }

   public void setUuid(String uuid) {
      this.uuid = uuid;
   }

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public Set<AccessRuleConnection> getConnections() {
      return this.connections;
   }

   public void addConnection(AccessRuleConnection connection) {
      this.connections.add(connection);
   }

   public void removeConnection(AccessRuleConnection connection) {
      this.connections.remove(connection);
   }

   public Set<ConnectionGroup> getConnectionGroups() {
      return this.connectionGroups;
   }

   public void addConnectionGroup(ConnectionGroup connectionGroup) {
      this.connectionGroups.add(connectionGroup);
   }

   public void removeConnectionGroup(ConnectionGroup connectionGroup) {
      this.connectionGroups.remove(connectionGroup);
   }

   public Bridge getBridge() {
      return this.bridge;
   }

   public void setBridge(Bridge bridge) {
      this.bridge = bridge;
   }

   public Set<User> getUsers() {
      return this.users;
   }

   public void addUser(User user) {
      if (!this.users.contains(user)) {
         this.users.add(user);
      }
   }

   public void removeUser(User user) {
      if (this.users.contains(user)) {
         this.users.remove(user);
      }
   }

   public Set<UserGroup> getUserGroups() {
      return this.userGroups;
   }

   public void addUserGroup(UserGroup userGroup) {
      if (!this.userGroups.contains(userGroup)) {
         this.userGroups.add(userGroup);
      }
   }

   public void removeUserGroup(UserGroup userGroup) {
      if (this.userGroups.contains(userGroup)) {
         this.userGroups.remove(userGroup);
      }
   }

   public boolean isDisabled() {
      return this.disabled;
   }

   public void setDisabled(boolean locked) {
      this.disabled = locked;
   }

   public long getExpirationTime() {
      return this.expirationTime;
   }

   public void setExpirationTime(long expirationDate) {
      this.expirationTime = expirationDate;
   }

   public FileTransferMode getFileTransferMode() {
      return this.fileTransferMode;
   }

   public void setFileTransferMode(FileTransferMode fileTransferMode) {
      this.fileTransferMode = fileTransferMode;
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

   public Set<Banner> getBanners() {
      return this.banners;
   }

   public void setBanners(Set<Banner> banners) {
      this.banners = banners;
   }

   public boolean isOcrEnabled() {
      return this.ocrEnabled;
   }

   public void setOcrEnabled(boolean ocrEnable) {
      this.ocrEnabled = ocrEnable;
   }

   public Set<SessionInputConstraintViolationHandler> getSessionInputConstraints() {
      return this.sessionInputConstraints;
   }

   public void setSessionInputConstraints(Set<SessionInputConstraintViolationHandler> sessionInputConstraints) {
      this.sessionInputConstraints = sessionInputConstraints;
   }

   public AccessibilityTimePeriodConstraint getAccessibilityTimePeriodConstraint() {
      return this.accessibilityTimePeriodConstraint;
   }

   public void setAccessibilityTimePeriodConstraint(AccessibilityTimePeriodConstraint accessibilityTimePeriodConstraint) {
      this.accessibilityTimePeriodConstraint = accessibilityTimePeriodConstraint;
   }

   public boolean isCaptureDisabled() {
      return this.captureDisabled;
   }

   public void setCaptureDisabled(boolean captureDisabled) {
      this.captureDisabled = captureDisabled;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (!(o instanceof AccessRule)) {
         return false;
      } else {
         AccessRule that = (AccessRule)o;
         return this.name.equals(that.name);
      }
   }

   @Override
   public int hashCode() {
      return Objects.hash(this.name);
   }
}
