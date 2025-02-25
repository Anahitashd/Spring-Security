package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;

public class KavoshServerNotConfiguredException extends AbstractException {
   @Override
   public String getCode() {
      return "kavosh.not_configured";
   }
}
