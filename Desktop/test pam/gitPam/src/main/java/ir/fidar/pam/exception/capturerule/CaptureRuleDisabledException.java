package ir.fidar.pam.exception.capturerule;

import ir.fidar.core.exception.api.AbstractException;

public class CaptureRuleDisabledException extends AbstractException {
   @Override
   public String getCode() {
      return "capture_rule.disabled";
   }
}
