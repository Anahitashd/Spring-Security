package ir.fidar.pam.exception.capturerule;

import ir.fidar.core.exception.api.AbstractException;
import ir.fidar.pam.domain.model.accessrule.AccessRule;

public class NoConnectionOrConnectionGroupIsProvidedException extends AbstractException {
   private final Class targetRule;

   public NoConnectionOrConnectionGroupIsProvidedException(Class targetRule) {
      this.targetRule = targetRule;
   }

   @Override
   public String getCode() {
      return this.targetRule.equals(AccessRule.class) ? "access_rule.connections.not_provided" : "capture_rule.connections.not_provided";
   }
}
