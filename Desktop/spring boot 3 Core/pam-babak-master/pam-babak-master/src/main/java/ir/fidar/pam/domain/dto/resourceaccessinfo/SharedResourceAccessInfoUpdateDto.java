package ir.fidar.pam.domain.dto.resourceaccessinfo;

import ir.fidar.core.security.validation.XssProtected;
import jakarta.validation.constraints.NotBlank;

public class SharedResourceAccessInfoUpdateDto {
   @NotBlank(
      message = "blank.label"
   )
   private String label;
   @NotBlank(
      message = "blank.owner"
   )
   private String owner;
   @XssProtected
   private String username;
   private String password;
   private String secretKey;

   public String getLabel() {
      return this.label;
   }

   public void setLabel(String label) {
      this.label = label;
   }

   public String getOwner() {
      return this.owner;
   }

   public void setOwner(String owner) {
      this.owner = owner;
   }

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

   public String getSecretKey() {
      return this.secretKey;
   }

   public void setSecretKey(String secretKey) {
      this.secretKey = secretKey;
   }
}
