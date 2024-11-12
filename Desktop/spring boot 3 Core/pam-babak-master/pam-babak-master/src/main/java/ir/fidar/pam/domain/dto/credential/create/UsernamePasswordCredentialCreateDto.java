package ir.fidar.pam.domain.dto.credential.create;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class UsernamePasswordCredentialCreateDto extends CredentialCreateDto {
   @NotBlank(
      message = "blank.username"
   )
   @Size(
      max = 255,
      message = "gt_max.username"
   )
   private String username;
   @Size(
      max = 255,
      message = "gt_max.password"
   )
   private String password;

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
}
