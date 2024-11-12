package ir.fidar.pam.exception.accessrule;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.Map;

public class AccessRuleIsAlreadySetOverConnectionThroughConnectionGroupException extends AbstractException {
   private final String connectionName;
   private final String connectionGroupName;
   private final String connectionConnectionGroupName;

   public AccessRuleIsAlreadySetOverConnectionThroughConnectionGroupException(
      String connectionName, String connectionGroupName, String connectionConnectionGroupName
   ) {
      this.connectionName = connectionName;
      this.connectionGroupName = connectionGroupName;
      this.connectionConnectionGroupName = connectionConnectionGroupName;
   }

   @Override
   public String getCode() {
      return this.connectionConnectionGroupName == null
         ? "access_rule.connections.alrdy_set_over_by_group"
         : "access_rule.connection_groups.connections.alrdy_set_over_by_another_group";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Map<String, Serializable> info = this.buildInfo().add("con", this.connectionName).add("group", this.connectionGroupName);
      if (this.connectionConnectionGroupName != null) {
         info.put("con-group", this.connectionConnectionGroupName);
      }

      return info;
   }
}
