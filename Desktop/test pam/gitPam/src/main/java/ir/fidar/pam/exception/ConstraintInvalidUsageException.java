package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractInternalException;

public class ConstraintInvalidUsageException extends AbstractInternalException {
   public ConstraintInvalidUsageException(String message) {
      super(message);
   }
}
