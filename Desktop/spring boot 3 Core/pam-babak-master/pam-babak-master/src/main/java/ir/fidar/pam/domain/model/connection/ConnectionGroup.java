package ir.fidar.pam.domain.model.connection;

import ir.fidar.core.domain.model.FullAuditionDescriptiveBaseEntity;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.management.log.crud.EnableAutoCrudLogging;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupCreateDto;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupUpdateDto;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.service.impl.connection.ConnectionGroupCrudServiceImpl;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Size;

@EnableAutoCrudLogging(
   displayName = "Connection Group",
   crudServiceImpl = ConnectionGroupCrudServiceImpl.class,
   createDto = ConnectionGroupCreateDto.class,
   updateDto = ConnectionGroupUpdateDto.class,
   uniquePropertyName = "Name"
)
@Entity
@Table(
   name = "tb_connection_group"
)
public class ConnectionGroup extends FullAuditionDescriptiveBaseEntity {
   @ValidName
   @Size(
      max = 48,
      message = "gt_max.name"
   )
   @XssProtected
   private String name;
   @ManyToMany(
      fetch = FetchType.LAZY,
      cascade = {CascadeType.MERGE}
   )
   @JoinTable(
      name = "tb_connection_group_connection",
      joinColumns = {@JoinColumn(
         name = "connection_group_id"
      )},
      inverseJoinColumns = {@JoinColumn(
         name = "connection_id"
      )}
   )
   private Set<Connection> connections = new HashSet<>();
   @ManyToMany(
      mappedBy = "connectionGroups",
      fetch = FetchType.LAZY
   )
   private Set<CaptureRule> captureRules;
   @ManyToMany(
      mappedBy = "connectionGroups",
      fetch = FetchType.LAZY
   )
   private Set<AccessRule> accessRules;

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

   public Set<CaptureRule> getCaptureRules() {
      return this.captureRules;
   }

   public Set<AccessRule> getAccessRules() {
      return this.accessRules;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (!(o instanceof ConnectionGroup)) {
         return false;
      } else {
         ConnectionGroup that = (ConnectionGroup)o;
         return this.name.equals(that.name);
      }
   }

   @Override
   public int hashCode() {
      return Objects.hash(this.name);
   }
}
