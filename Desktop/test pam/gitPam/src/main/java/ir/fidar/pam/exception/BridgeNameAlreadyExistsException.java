package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;

public class BridgeNameAlreadyExistsException extends AbstractException {
   @Override
   public String getCode() {
      return "bridge.name.dup";
   }
}
