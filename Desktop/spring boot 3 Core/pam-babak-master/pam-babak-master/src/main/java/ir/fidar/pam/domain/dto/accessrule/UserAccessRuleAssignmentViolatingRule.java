package ir.fidar.pam.domain.dto.accessrule;

public class UserAccessRuleAssignmentViolatingRule {
   private final String accessRule;
   private final String user;
   private final String userGroup;

   public UserAccessRuleAssignmentViolatingRule(String accessRule, String user, String userGroup) {
      this.accessRule = accessRule;
      this.user = user;
      this.userGroup = userGroup;
   }

   public String getAccessRule() {
      return this.accessRule;
   }

   public String getUser() {
      return this.user;
   }

   public String getUserGroup() {
      return this.userGroup;
   }
}
