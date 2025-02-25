package ir.fidar.pam.exception.connection;

import ir.fidar.core.exception.api.AbstractInternalException;

public class ConnectionTypeNotSupportedException extends AbstractInternalException {
   public ConnectionTypeNotSupportedException(String message) {
      super(message);
   }
}
