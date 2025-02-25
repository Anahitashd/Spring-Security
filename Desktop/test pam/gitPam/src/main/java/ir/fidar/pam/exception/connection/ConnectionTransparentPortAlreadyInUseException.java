package ir.fidar.pam.exception.connection;

import ir.fidar.core.exception.api.AbstractException;

public class ConnectionTransparentPortAlreadyInUseException extends AbstractException {
   @Override
   public String getCode() {
      return "con.trans_port.dup";
   }
}
