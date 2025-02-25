package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;

public class NoImagesCapturedFromSessionBasedOnRuleException extends AbstractException {
   @Override
   public String getCode() {
      return "capture.no_captured_images";
   }

   @Override
   public int getMappedHttpCode() {
      return 200;
   }
}
