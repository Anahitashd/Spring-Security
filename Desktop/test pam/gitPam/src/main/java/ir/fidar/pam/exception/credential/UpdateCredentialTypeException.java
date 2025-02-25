package ir.fidar.pam.exception.credential;

import ir.fidar.core.exception.api.AbstractException;

public class UpdateCredentialTypeException extends AbstractException {
   @Override
   public String getCode() {
      return "cred.type.upd_unsupported";
   }
}
