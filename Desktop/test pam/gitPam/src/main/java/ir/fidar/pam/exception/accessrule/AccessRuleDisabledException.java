package ir.fidar.pam.exception.accessrule;

import ir.fidar.core.exception.api.AbstractException;

public class AccessRuleDisabledException extends AbstractException {
   @Override
   public String getCode() {
      return "access_rule.disabled";
   }
}
