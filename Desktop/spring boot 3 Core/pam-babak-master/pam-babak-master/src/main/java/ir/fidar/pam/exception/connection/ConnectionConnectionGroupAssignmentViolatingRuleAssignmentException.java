package ir.fidar.pam.exception.connection;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.Map;

public class ConnectionConnectionGroupAssignmentViolatingRuleAssignmentException extends AbstractException {
   private final String connectionGroupName;
   private final String ruleName;
   private final String connectionConnectionGroup;

   public ConnectionConnectionGroupAssignmentViolatingRuleAssignmentException(String connectionGroupName, String ruleName, String connectionConnectionGroup) {
      this.connectionGroupName = connectionGroupName;
      this.ruleName = ruleName;
      this.connectionConnectionGroup = connectionConnectionGroup;
   }

   @Override
   public String getCode() {
      return this.connectionConnectionGroup == null
         ? "con.con_groups.assignment_violating_rule_assignment"
         : "con.con_groups.assignment_violating_rule_assignment_through_another_group";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Map<String, Serializable> info = this.buildInfo().add("group", this.connectionGroupName).add("rule-name", this.ruleName);
      if (this.connectionConnectionGroup != null) {
         info.put("connection-group", this.connectionConnectionGroup);
      }

      return info;
   }
}
