package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;

public class ConnectionGroupNameAlreadyInUseException extends AbstractException {
   @Override
   public String getCode() {
      return "con_group.name.dup";
   }
}
