package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;
import ir.fidar.core.exception.api.Exception;
import ir.fidar.core.management.response.Utility;
import ir.fidar.core.util.StringUtils;
import java.io.Serializable;
import java.util.Map;

public class IneligibleUserGroupMembershipException extends AbstractException {
   private static final String CODE_FORMAT = "user_group.users.rule_con_accessibility_ineligible_membership%s";
   private final String userUsername;
   private final String ruleName;
   private final String connectionName;
   private final String userGroupName;
   private final Class targetRule;

   public IneligibleUserGroupMembershipException(String userUsername, String ruleName, String connectionName, Class targetRule) {
      this(userUsername, ruleName, connectionName, null, targetRule);
   }

   public IneligibleUserGroupMembershipException(String userUsername, String ruleName, String connectionName, String userGroupName, Class targetRule) {
      this.userUsername = userUsername;
      this.ruleName = ruleName;
      this.connectionName = connectionName;
      this.userGroupName = userGroupName;
      this.targetRule = targetRule;
   }

   @Override
   public String getCode() {
      return String.format("user_group.users.rule_con_accessibility_ineligible_membership%s", StringUtils.hasContent(this.connectionName) ? "_by_group" : "");
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Exception.InfoBuilder info = this.buildInfo()
         .add("user", this.userUsername)
         .add("rule", Utility.getSectionName(this.targetRule))
         .add("rule-name", this.ruleName)
         .add("con", this.connectionName);
      if (StringUtils.hasContent(this.userGroupName)) {
         info.add("group", this.userGroupName);
      }

      return info;
   }
}
