package ir.fidar.pam.domain.model.credential;

import ir.fidar.core.security.validation.XssProtected;
import jakarta.persistence.Entity;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Entity
@Table(
   name = "tb_private_key_credential"
)
public class PrivateKeyCredential extends Credential {
   @NotBlank(
      message = "blank.username"
   )
   @Size(
      max = 255,
      message = "gt_max.username"
   )
   @XssProtected
   private String username;
   @NotBlank(
      message = "blank.privateKey"
   )
   @Lob
   private String privateKey;
   @Size(
      max = 255,
      message = "wrng_size.passphrase"
   )
   private String passphrase;

   public String getUsername() {
      return this.username;
   }

   public void setUsername(String username) {
      this.username = username;
   }

   public String getPrivateKey() {
      return this.privateKey;
   }

   public void setPrivateKey(String private_kay) {
      this.privateKey = private_kay;
   }

   public String getPassphrase() {
      return this.passphrase;
   }

   public void setPassphrase(String passphrase) {
      this.passphrase = passphrase;
   }
}
