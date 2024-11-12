package ir.fidar.pam.exception.sessioninputconstraint;

import ir.fidar.core.exception.api.AbstractException;

public class SessionInputConstraintNameAlreadyExistsException extends AbstractException {
   @Override
   public String getCode() {
      return "session_input_const.name.dup";
   }
}
