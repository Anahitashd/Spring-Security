package ir.fidar.pam.exception.connection;

import ir.fidar.core.exception.api.AbstractException;
import ir.fidar.pam.domain.type.CredentialType;
import java.io.Serializable;
import java.util.Map;

public class UnsupportedCredentialTypeByConnectionException extends AbstractException {
   private CredentialType credentialType;

   public UnsupportedCredentialTypeByConnectionException(CredentialType credentialType) {
      this.credentialType = credentialType;
   }

   @Override
   public String getCode() {
      return "con.cred.unsupported_type";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      return this.buildInfo().add("type", this.credentialType.toString());
   }
}
