package ir.fidar.pam.exception.accessrule;

import ir.fidar.core.exception.api.AbstractException;

public class AccessRuleNameAlreadyExistsException extends AbstractException {
   @Override
   public String getCode() {
      return "access_rule.name.dup";
   }
}
