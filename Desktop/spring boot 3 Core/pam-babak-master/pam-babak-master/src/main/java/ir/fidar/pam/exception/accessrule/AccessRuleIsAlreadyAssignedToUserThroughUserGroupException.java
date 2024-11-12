package ir.fidar.pam.exception.accessrule;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.Map;

public class AccessRuleIsAlreadyAssignedToUserThroughUserGroupException extends AbstractException {
   private final String userUsername;
   private final String userGroupName;
   private final String userUserGroupName;

   public AccessRuleIsAlreadyAssignedToUserThroughUserGroupException(String userUsername, String userGroupName, String userUserGroupName) {
      this.userUsername = userUsername;
      this.userGroupName = userGroupName;
      this.userUserGroupName = userUserGroupName;
   }

   @Override
   public String getCode() {
      return this.userUserGroupName == null ? "access_rule.users.alrdy_access_by_group" : "access_rule.user_groups.users.alrdy_access_by_another_group";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Map<String, Serializable> info = this.buildInfo().add("user", this.userUsername).add("group", this.userGroupName);
      if (this.userUserGroupName != null) {
         info.put("user-group", this.userUserGroupName);
      }

      return info;
   }
}
