package ir.fidar.pam.exception.connection;

import ir.fidar.core.exception.api.AbstractException;

public class RemoteApplicationOnlySupportedByRdpConnectionException extends AbstractException {
   @Override
   public String getCode() {
      return "con.remote_app.not_supported";
   }
}
