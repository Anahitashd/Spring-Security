package ir.fidar.pam.service;

import ir.fidar.core.service.generic.GenericService;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.exception.connection.NoCaptureRuleIsFoundForConnectionException;

public interface CaptureRuleService extends GenericService<CaptureRule, String> {
   void delete(Long var1);

   CaptureRuleService.AccessibilityStatus checkUserAccessibilityOverConnection(String var1) throws NoCaptureRuleIsFoundForConnectionException;

   CaptureRule getCaptureRuleOfUserOverConnection(Long var1, Long var2);

   public static enum AccessibilityStatus {
      NOT_PRIVILEGED,
      NOT_EXPORTABLE,
      EXPIRED,
      DISABLED,
      ACCESSIBLE;
   }
}
