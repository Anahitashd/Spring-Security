package ir.fidar.pam.domain.model;

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
import ir.fidar.pam.domain.dto.capturerule.CaptureRuleCreateDto;
import ir.fidar.pam.domain.dto.capturerule.CaptureRuleUpdateDto;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.connection.ConnectionGroup;
import ir.fidar.pam.domain.model.management.User;
import ir.fidar.pam.domain.model.management.UserGroup;
import ir.fidar.pam.service.impl.CaptureRuleCrudServiceImpl;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;

@Secure(
   section = "CAPTURE_RULE",
   crud = @CrudPrivilege(
      baseURLs = {"/api/capture-rules/*", "/api/management/users/*/capture-rules", "/api/management/user-groups/*/capture-rules", "/api/connections/*/capture-rules", "/api/connection-groups/*/capture-rules"},
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
      )})
)
@EnableAutoCrudLogging(
   displayName = "Capture Rule",
   crudServiceImpl = CaptureRuleCrudServiceImpl.class,
   createDto = CaptureRuleCreateDto.class,
   updateDto = CaptureRuleUpdateDto.class,
   uniquePropertyName = "Name"
)
@Entity
@Table(
   name = "tb_capture_rule"
)
public class CaptureRule extends FullAuditionDescriptiveBaseEntity {
   @ValidName
   @Size(
      max = 48,
      message = "gt_max.name"
   )
   @XssProtected
   private String name;
   @ManyToMany(
      fetch = FetchType.LAZY
   )
   @JoinTable(
      name = "tb_capture_rule_connection",
      joinColumns = {@JoinColumn(
         name = "capture_rule_id"
      )},
      inverseJoinColumns = {@JoinColumn(
         name = "connection_id"
      )}
   )
   private Set<Connection> connections = new HashSet<>();
   @ManyToMany(
      fetch = FetchType.LAZY
   )
   @JoinTable(
      name = "tb_capture_rule_connection_group",
      joinColumns = {@JoinColumn(
         name = "capture_rule_id"
      )},
      inverseJoinColumns = {@JoinColumn(
         name = "connection_group_id"
      )}
   )
   private Set<ConnectionGroup> connectionGroups = new HashSet<>();
   @ManyToMany(
      fetch = FetchType.LAZY
   )
   @JoinTable(
      name = "tb_capture_rule_user",
      joinColumns = {@JoinColumn(
         name = "capture_rule_id"
      )},
      inverseJoinColumns = {@JoinColumn(
         name = "user_id"
      )}
   )
   private Set<User> users = new HashSet<>();
   @ManyToMany(
      fetch = FetchType.LAZY
   )
   @JoinTable(
      name = "tb_capture_rule_user_group",
      joinColumns = {@JoinColumn(
         name = "capture_rule_id"
      )},
      inverseJoinColumns = {@JoinColumn(
         name = "user_group_id"
      )}
   )
   private Set<UserGroup> userGroups = new HashSet<>();
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

   public Set<Connection> getConnections() {
      return this.connections;
   }

   public void addConnection(Connection connection) {
      if (!this.connections.contains(connection)) {
         this.connections.add(connection);
      }
   }

   public void removeConnection(Connection connection) {
      if (this.connections.contains(connection)) {
         this.connections.remove(connection);
      }
   }

   public Set<ConnectionGroup> getConnectionGroups() {
      return this.connectionGroups;
   }

   public void addConnectionGroup(ConnectionGroup connectionGroup) {
      if (!this.connectionGroups.contains(connectionGroup)) {
         this.connectionGroups.add(connectionGroup);
      }
   }

   public void removeConnectionGroup(ConnectionGroup connectionGroup) {
      if (this.connectionGroups.contains(connectionGroup)) {
         this.connectionGroups.remove(connectionGroup);
      }
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

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (!(o instanceof CaptureRule)) {
         return false;
      } else {
         CaptureRule that = (CaptureRule)o;
         return this.name.equals(that.name);
      }
   }

   @Override
   public int hashCode() {
      return Objects.hash(this.name);
   }
}
