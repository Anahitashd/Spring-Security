package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;

public class SymmetricKeyAlreadyRegisteredException extends AbstractException {
   @Override
   public String getCode() {
      return "symmetric_key.alrdy_registered";
   }
}
