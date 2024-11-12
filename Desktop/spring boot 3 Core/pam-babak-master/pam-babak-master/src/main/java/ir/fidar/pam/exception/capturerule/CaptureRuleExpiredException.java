package ir.fidar.pam.exception.capturerule;

import ir.fidar.core.exception.api.AbstractException;

public class CaptureRuleExpiredException extends AbstractException {
   @Override
   public String getCode() {
      return "capture_rule.expired";
   }
}
