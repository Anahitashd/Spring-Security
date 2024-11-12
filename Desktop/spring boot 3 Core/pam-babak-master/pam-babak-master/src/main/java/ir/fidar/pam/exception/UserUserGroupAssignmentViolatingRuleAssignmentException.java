package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;
import ir.fidar.core.management.response.Utility;
import java.io.Serializable;
import java.util.Map;

public class UserUserGroupAssignmentViolatingRuleAssignmentException extends AbstractException {
   private final String userGroupName;
   private final String ruleName;
   private final Class targetRule;
   private final String userUserGroup;

   public UserUserGroupAssignmentViolatingRuleAssignmentException(String userGroupName, String ruleName, Class targetRule) {
      this(userGroupName, ruleName, targetRule, null);
   }

   public UserUserGroupAssignmentViolatingRuleAssignmentException(String userGroupName, String ruleName, Class targetRule, String userUserGroup) {
      this.userGroupName = userGroupName;
      this.ruleName = ruleName;
      this.targetRule = targetRule;
      this.userUserGroup = userUserGroup;
   }

   @Override
   public String getCode() {
      return this.userUserGroup == null
         ? "user.user_groups.assignment_violating_rule_assignment"
         : "user.user_groups.assignment_violating_rule_assignment_through_another_group";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Map<String, Serializable> info = this.buildInfo()
         .add("group", this.userGroupName)
         .add("rule", Utility.getSectionName(this.targetRule))
         .add("rule-name", this.ruleName);
      if (this.userUserGroup != null) {
         info.put("user-group", this.userUserGroup);
      }

      return info;
   }
}
