package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

public class DeleteBridgeUsedByAccessRuleException extends AbstractException {
   private List<String> accessRuleNames;

   public DeleteBridgeUsedByAccessRuleException(List<String> accessRuleNames) {
      this.accessRuleNames = accessRuleNames;
   }

   @Override
   public String getCode() {
      return "bridge.del.used_by_access_rule";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      return this.buildInfo().add("access-rules", this.accessRuleNames.toString());
   }
}
