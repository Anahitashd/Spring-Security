package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;
import ir.fidar.pam.domain.model.accessrule.AccessRule;

public class NoUserOrUserGroupProvidedException extends AbstractException {
   private final Class targetRule;

   public NoUserOrUserGroupProvidedException(Class targetRule) {
      this.targetRule = targetRule;
   }

   @Override
   public String getCode() {
      return this.targetRule.equals(AccessRule.class) ? "access_rule.users.not_provided" : "capture_rule.users.not_provided";
   }
}
