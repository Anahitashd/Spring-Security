package ir.fidar.pam.domain.dto.credential.details;

public class DomainCredentialDetailsDto extends CredentialDetailsDto {
   private String username;
   private String domain;

   public String getUsername() {
      return this.username;
   }

   public void setUsername(String username) {
      this.username = username;
   }

   public String getDomain() {
      return this.domain;
   }

   public void setDomain(String domain) {
      this.domain = domain;
   }
}
