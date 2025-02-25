package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;
import ir.fidar.core.management.response.Utility;
import java.io.Serializable;
import java.util.Map;

public class UserGroupUserMembershipViolatingRuleAssignmentException extends AbstractException {
   private final String userUsername;
   private final String ruleName;
   private final Class targetRule;
   private final String userUserGroup;

   public UserGroupUserMembershipViolatingRuleAssignmentException(String userUsername, String ruleName, Class targetRule) {
      this(userUsername, ruleName, targetRule, null);
   }

   public UserGroupUserMembershipViolatingRuleAssignmentException(String userUsername, String ruleName, Class targetRule, String userUserGroup) {
      this.userUsername = userUsername;
      this.ruleName = ruleName;
      this.targetRule = targetRule;
      this.userUserGroup = userUserGroup;
   }

   @Override
   public String getCode() {
      return this.userUserGroup == null
         ? "user_group.users.membership_violating_rule_assignment"
         : "user_group.users.membership_violating_rule_assignment_through_another_group";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Map<String, Serializable> info = this.buildInfo()
         .add("user", this.userUsername)
         .add("rule", Utility.getSectionName(this.targetRule))
         .add("rule-name", this.ruleName);
      if (this.userUserGroup != null) {
         info.put("user-group", this.userUserGroup);
      }

      return info;
   }
}
