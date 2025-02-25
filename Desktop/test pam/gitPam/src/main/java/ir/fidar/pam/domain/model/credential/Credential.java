package ir.fidar.pam.domain.model.credential;

import ir.fidar.core.domain.model.BaseEntity;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.type.CredentialType;
import ir.fidar.pam.domain.util.converter.attribbute.CredentialTypeConverter;
import java.util.Objects;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(
   name = "tb_credential"
)
@Inheritance(
   strategy = InheritanceType.JOINED
)
public class Credential extends BaseEntity {
   @NotNull(
      message = "null.type"
   )
   @Convert(
      converter = CredentialTypeConverter.class
   )
   private CredentialType type;
   @ValidName
   @Size(
      max = 48,
      message = "gt_max.label"
   )
   @XssProtected
   private String label;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "connection_id"
   )
   private Connection connection;

   public CredentialType getType() {
      return this.type;
   }

   public void setType(CredentialType type) {
      this.type = type;
   }

   public String getLabel() {
      return this.label;
   }

   public void setLabel(String label) {
      this.label = label;
   }

   public Connection getConnection() {
      return this.connection;
   }

   public void setConnection(Connection connection) {
      this.connection = connection;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (!(o instanceof Credential)) {
         return false;
      } else {
         Credential that = (Credential)o;
         return this.label.equals(that.label);
      }
   }

   @Override
   public int hashCode() {
      return Objects.hash(this.label);
   }
}
