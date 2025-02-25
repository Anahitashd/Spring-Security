package ir.fidar.pam.domain.model.credential;

import ir.fidar.core.security.validation.XssProtected;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Entity
@Table(
   name = "tb_domain_credential"
)
public class DomainCredential extends Credential {
   @NotBlank(
      message = "blank.username"
   )
   @Size(
      max = 255,
      message = "gt_max.username"
   )
   @XssProtected
   private String username;
   @Size(
      max = 255,
      message = "gt_max.password"
   )
   private String password;
   @NotBlank(
      message = "blank.domain"
   )
   @Size(
      max = 255,
      message = "gt_max.domain"
   )
   @XssProtected
   private String domain;

   public String getUsername() {
      return this.username;
   }

   public void setUsername(String username) {
      this.username = username;
   }

   public String getPassword() {
      return this.password;
   }

   public void setPassword(String password) {
      this.password = password;
   }

   public String getDomain() {
      return this.domain;
   }

   public void setDomain(String domain) {
      this.domain = domain;
   }
}
