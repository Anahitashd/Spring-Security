package ir.fidar.pam.domain.dto.credential.create;

import ir.fidar.core.security.validation.XssProtected;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

public class PrivateKeyCredentialCreateDto extends CredentialCreateDto {
   @NotBlank(
      message = "blank.username"
   )
   @Size(
      max = 255,
      message = "gt_max.username"
   )
   @XssProtected
   private String username;
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

   public void setPrivateKey(String privateKey) {
      this.privateKey = privateKey;
   }

   public String getPassphrase() {
      return this.passphrase;
   }

   public void setPassphrase(String passphrase) {
      this.passphrase = passphrase;
   }
}
