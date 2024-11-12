package ir.fidar.pam.domain.dto.credential.details;

import ir.fidar.pam.domain.type.CredentialType;

public class CredentialDetailsDto {
   private CredentialType type;
   private String label;

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
}
