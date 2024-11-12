package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;
import ir.fidar.core.exception.api.Exception;
import ir.fidar.core.management.response.Utility;
import ir.fidar.core.util.StringUtils;
import java.io.Serializable;
import java.util.Map;

public class IneligibleUserGroupAssignmentException extends AbstractException {
   private static final String CODE_FORMAT = "user.user_groups.rule_con_accessibility_ineligible_assignment%s";
   private final String userGroupName;
   private final String ruleName;
   private final String connectionName;
   private final String targetUserGroupName;
   private final Class targetRule;

   public IneligibleUserGroupAssignmentException(String userGroupName, String ruleName, String connectionName, Class targetRule) {
      this(userGroupName, ruleName, connectionName, null, targetRule);
   }

   public IneligibleUserGroupAssignmentException(String userGroupName, String ruleName, String connectionName, String targetUserGroupName, Class targetRule) {
      this.userGroupName = userGroupName;
      this.ruleName = ruleName;
      this.connectionName = connectionName;
      this.targetUserGroupName = targetUserGroupName;
      this.targetRule = targetRule;
   }

   @Override
   public String getCode() {
      boolean hasGroup = StringUtils.hasContent(this.userGroupName);
      return String.format("user.user_groups.rule_con_accessibility_ineligible_assignment%s", hasGroup ? "_by_group" : "");
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Exception.InfoBuilder info = this.buildInfo()
         .add("group", this.userGroupName)
         .add("rule", Utility.getSectionName(this.targetRule))
         .add("rule-name", this.ruleName)
         .add("con", this.connectionName);
      if (StringUtils.hasContent(this.targetUserGroupName)) {
         info.add("another-group", this.targetUserGroupName);
      }

      return info;
   }
}
