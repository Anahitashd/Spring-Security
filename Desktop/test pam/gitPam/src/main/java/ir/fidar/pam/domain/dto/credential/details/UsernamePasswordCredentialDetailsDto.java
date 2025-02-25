package ir.fidar.pam.domain.dto.credential.details;

public class UsernamePasswordCredentialDetailsDto extends CredentialDetailsDto {
   private String username;

   public String getUsername() {
      return this.username;
   }

   public void setUsername(String username) {
      this.username = username;
   }
}
