package ir.fidar.pam.domain.model.accessrule;

import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.connection.RdpConnectionRemoteApplication;
import ir.fidar.pam.domain.model.credential.Credential;
import java.util.Objects;
import javax.persistence.CascadeType;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.MapsId;
import javax.persistence.Table;

@Entity
@Table(
   name = "tb_access_rule_connection"
)
public class AccessRuleConnection {
   @EmbeddedId
   private AccessRuleConnectionId id;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @MapsId("accessRuleId")
   private AccessRule accessRule;
   @ManyToOne(
      fetch = FetchType.EAGER,
      cascade = {CascadeType.PERSIST, CascadeType.MERGE}
   )
   @MapsId("connectionId")
   private Connection connection;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "credential_id"
   )
   private Credential credential;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "rdp_remote_application_id"
   )
   private RdpConnectionRemoteApplication rdpConnectionRemoteApplication;

   public AccessRuleConnection() {
   }

   public AccessRuleConnection(AccessRule accessRule, Connection connection) {
      this.accessRule = accessRule;
      this.connection = connection;
      this.id = new AccessRuleConnectionId(accessRule.getId(), connection.getId());
   }

   public AccessRuleConnectionId getId() {
      return this.id;
   }

   public AccessRule getAccessRule() {
      return this.accessRule;
   }

   public void setAccessRule(AccessRule accessRule) {
      this.accessRule = accessRule;
   }

   public Connection getConnection() {
      return this.connection;
   }

   public void setConnection(Connection connection) {
      this.connection = connection;
   }

   public Credential getCredential() {
      return this.credential;
   }

   public void setCredential(Credential credential) {
      this.credential = credential;
   }

   public RdpConnectionRemoteApplication getRdpConnectionRemoteApplication() {
      return this.rdpConnectionRemoteApplication;
   }

   public void setRdpConnectionRemoteApplication(RdpConnectionRemoteApplication rdpConnectionRemoteApplication) {
      this.rdpConnectionRemoteApplication = rdpConnectionRemoteApplication;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (o != null && this.getClass() == o.getClass()) {
         AccessRuleConnection that = (AccessRuleConnection)o;
         return this.id.equals(that.id);
      } else {
         return false;
      }
   }

   @Override
   public int hashCode() {
      return Objects.hash(this.id);
   }
}
