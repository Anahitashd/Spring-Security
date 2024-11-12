package ir.fidar.pam.exception.sessioninputconstraint;

import ir.fidar.core.exception.api.AbstractException;

public class DeleteInUseSessionInputConstraintException extends AbstractException {
   @Override
   public String getCode() {
      return "session_input_const.del.in_use";
   }
}
