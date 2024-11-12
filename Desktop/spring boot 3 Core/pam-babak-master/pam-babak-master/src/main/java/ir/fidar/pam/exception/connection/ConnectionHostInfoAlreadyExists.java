package ir.fidar.pam.exception.connection;

import ir.fidar.core.exception.api.AbstractException;

public class ConnectionHostInfoAlreadyExists extends AbstractException {
   @Override
   public String getCode() {
      return "con.host_info.dup";
   }
}
