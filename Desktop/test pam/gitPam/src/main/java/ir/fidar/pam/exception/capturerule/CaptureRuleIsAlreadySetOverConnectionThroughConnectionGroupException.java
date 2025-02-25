package ir.fidar.pam.exception.capturerule;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.Map;

public class CaptureRuleIsAlreadySetOverConnectionThroughConnectionGroupException extends AbstractException {
   private final String connectionName;
   private final String connectionGroupName;

   public CaptureRuleIsAlreadySetOverConnectionThroughConnectionGroupException(String connectionName, String connectionGroupName) {
      this.connectionName = connectionName;
      this.connectionGroupName = connectionGroupName;
   }

   @Override
   public String getCode() {
      return "capture_rule.connections.alrdy_set_over_by_group";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      return this.buildInfo().add("con", this.connectionName).add("group", this.connectionGroupName);
   }
}
