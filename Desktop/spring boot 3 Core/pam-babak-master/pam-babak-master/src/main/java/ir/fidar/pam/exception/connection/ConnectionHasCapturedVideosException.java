package ir.fidar.pam.exception.connection;

import ir.fidar.core.exception.api.AbstractException;

public class ConnectionHasCapturedVideosException extends AbstractException {
   @Override
   public String getCode() {
      return "con.del.has_captured_session";
   }
}
