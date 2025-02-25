package ir.fidar.pam.exception.credential;

import ir.fidar.core.exception.api.AbstractException;
import ir.fidar.pam.domain.type.CredentialType;
import java.io.Serializable;
import java.util.Map;

public class UnsupportedCredentialTypeException extends AbstractException {
   private CredentialType type;

   public UnsupportedCredentialTypeException(CredentialType type) {
      this.type = type;
   }

   @Override
   public String getCode() {
      return "cred.type.unsupported";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      return this.buildInfo().add("type", this.type);
   }
}
