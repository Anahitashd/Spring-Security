package ir.fidar.pam.domain.dto.credential.create;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class DomainCredentialCreateDto extends CredentialCreateDto {
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
   @NotBlank(
      message = "blank.domain"
   )
   @Size(
      max = 255,
      message = "gt_max.domain"
   )
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
