package ir.fidar.pam.exception.capturerule;

import ir.fidar.core.exception.api.AbstractException;

public class CaptureRuleNameAlreadyExists extends AbstractException {
   @Override
   public String getCode() {
      return "capture_rule.name.dup";
   }
}
