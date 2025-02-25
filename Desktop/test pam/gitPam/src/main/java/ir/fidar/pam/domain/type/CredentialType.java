package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum CredentialType implements PersistentEnum {
   USERNAME_PASSWORD(1),
   DOMAIN(2),
   PRIVATE_KEY(3);

   private int code;

   private CredentialType(int code) {
      this.code = code;
   }

   @Override
   public int getCode() {
      return this.code;
   }
}
