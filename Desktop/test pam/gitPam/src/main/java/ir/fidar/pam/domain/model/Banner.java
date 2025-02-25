package ir.fidar.pam.domain.model;

import ir.fidar.core.domain.model.BaseEntity;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.domain.model.connection.Connection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(
   name = "tb_banner"
)
public class Banner extends BaseEntity {
   @NotNull(
      message = "null.message"
   )
   @NotBlank(
      message = "blank.message"
   )
   @Size(
      min = 1,
      max = 255,
      message = "wrng_size.message"
   )
   @XssProtected
   private String message;
   private boolean skippable;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "access_rule_id"
   )
   private AccessRule accessRule;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "connection_id"
   )
   private Connection connection;

   public String getMessage() {
      return this.message;
   }

   public void setMessage(String message) {
      this.message = message;
   }

   public boolean isSkippable() {
      return this.skippable;
   }

   public void setSkippable(boolean skippable) {
      this.skippable = skippable;
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
}
