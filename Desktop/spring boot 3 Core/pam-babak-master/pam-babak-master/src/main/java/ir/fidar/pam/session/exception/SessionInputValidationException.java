package ir.fidar.pam.session.exception;

import ir.fidar.pam.domain.model.SessionInputConstraintViolationHandler;

public class SessionInputValidationException extends Exception {
   private final SessionInputConstraintViolationHandler handler;
   private final String input;

   public SessionInputValidationException(SessionInputConstraintViolationHandler handler, String input) {
      this.handler = handler;
      this.input = input;
   }

   public SessionInputConstraintViolationHandler getHandler() {
      return this.handler;
   }

   public String getInput() {
      return this.input;
   }
}
