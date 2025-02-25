package ir.fidar.pam.exception.connection;

import ir.fidar.core.exception.api.AbstractException;

public class ConnectionNameAlreadyExistsException extends AbstractException {
   @Override
   public String getCode() {
      return "con.name.dup";
   }
}
