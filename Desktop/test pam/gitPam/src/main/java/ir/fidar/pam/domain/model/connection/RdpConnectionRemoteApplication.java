package ir.fidar.pam.domain.model.connection;

import ir.fidar.core.domain.model.BaseEntity;
import ir.fidar.core.security.validation.CustomizedXssProtected;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.model.accessrule.AccessRuleConnection;
import java.util.Objects;
import java.util.Set;
import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Entity
@Table(
   name = "tb_rdp_connection_remote_application"
)
public class RdpConnectionRemoteApplication extends BaseEntity {
   @NotBlank(
      message = "blank.name"
   )
   @Size(
      max = 64,
      message = "gt_max.name"
   )
   @XssProtected
   private String name;
   @Size(
      max = 255,
      message = "gt_max.workingDirectory"
   )
   @CustomizedXssProtected(
      skippingCharacters = {'/', '\\', ':'}
   )
   private String workingDirectory;
   @Size(
      max = 255,
      message = "gt_max.params"
   )
   private String params;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "connection_id"
   )
   private RdpConnection connection;
   @OneToMany(
      fetch = FetchType.LAZY,
      mappedBy = "rdpConnectionRemoteApplication",
      cascade = {CascadeType.REMOVE}
   )
   private Set<AccessRuleConnection> accessRules;

   public String getName() {
      return this.name;
   }

   public void setName(String remoteAppName) {
      this.name = remoteAppName;
   }

   public String getWorkingDirectory() {
      return this.workingDirectory;
   }

   public void setWorkingDirectory(String remoteAppWorkingDirectory) {
      this.workingDirectory = remoteAppWorkingDirectory;
   }

   public String getParams() {
      return this.params;
   }

   public void setParams(String remoteAppParams) {
      this.params = remoteAppParams;
   }

   public RdpConnection getConnection() {
      return this.connection;
   }

   public void setConnection(RdpConnection connection) {
      this.connection = connection;
   }

   public Set<AccessRuleConnection> getAccessRules() {
      return this.accessRules;
   }

   public void setAccessRules(Set<AccessRuleConnection> accessRule) {
      this.accessRules = accessRule;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (!(o instanceof RdpConnectionRemoteApplication)) {
         return false;
      } else {
         RdpConnectionRemoteApplication that = (RdpConnectionRemoteApplication)o;
         return this.name.equals(that.name);
      }
   }

   @Override
   public int hashCode() {
      return Objects.hash(this.name);
   }
}
