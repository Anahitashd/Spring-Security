package ir.fidar.pam.exception.accessrule;

import ir.fidar.core.exception.api.Exception;
import java.io.Serializable;
import java.util.Map;

public class UserGroupUserAlreadyAccessConnectionByAnotherAccessRuleException extends UserAlreadyAccessConnectionByAnotherAccessRuleException {
   private final String userGroupName;

   public UserGroupUserAlreadyAccessConnectionByAnotherAccessRuleException(
      String userUsername, String accessRuleName, String connectionName, String connectionGroupName, String userGroupName
   ) {
      super(userUsername, accessRuleName, connectionName, connectionGroupName);
      this.userGroupName = userGroupName;
   }

   @Override
   public String getCode() {
      return super.connectionGroupName == null ? "access_rule.user_groups.user_alrdy_access_con" : "access_rule.user_groups.user_alrdy_access_grouped_con";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Exception.InfoBuilder info = (Exception.InfoBuilder)super.getInfo();
      info.add("user-group", this.userGroupName);
      return info;
   }
}
