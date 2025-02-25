package ir.fidar.pam.exception.connection;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.Map;

public class ConnectionGroupConnectionMembershipViolatingAccessRuleAssignmentException extends AbstractException {
   private final String connectionName;
   private final String accessRuleName;
   private final String connectionConnectionGroup;

   public ConnectionGroupConnectionMembershipViolatingAccessRuleAssignmentException(
      String connectionName, String accessRuleName, String connectionConnectionGroup
   ) {
      this.connectionName = connectionName;
      this.accessRuleName = accessRuleName;
      this.connectionConnectionGroup = connectionConnectionGroup;
   }

   @Override
   public String getCode() {
      return this.connectionConnectionGroup == null
         ? "con_group.cons.membership_violating_rule_assignment"
         : "con_group.cons.membership_violating_rule_assignment_through_another_group";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Map<String, Serializable> info = this.buildInfo().add("connection", this.connectionName).add("rule-name", this.accessRuleName);
      if (this.connectionConnectionGroup != null) {
         info.put("connection-group", this.connectionConnectionGroup);
      }

      return info;
   }
}
