package ir.fidar.pam.exception.accessrule;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.Map;

public class UserAlreadyAccessConnectionByAnotherAccessRuleException extends AbstractException {
   private final String userUsername;
   private final String accessRuleName;
   protected final String connectionName;
   protected final String connectionGroupName;

   public UserAlreadyAccessConnectionByAnotherAccessRuleException(String userUsername, String accessRuleName, String connectionName, String connectionGroupName) {
      this.userUsername = userUsername;
      this.accessRuleName = accessRuleName;
      this.connectionName = connectionName;
      this.connectionGroupName = connectionGroupName;
   }

   @Override
   public String getCode() {
      return this.connectionGroupName == null ? "access_rule.users.alrdy_access_con" : "access_rule.users.alrdy_access_grouped_con";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Map<String, Serializable> info = this.buildInfo().add("access-rule", this.accessRuleName).add("user", this.userUsername).add("con", this.connectionName);
      if (this.connectionGroupName != null) {
         info.put("con-group", this.connectionGroupName);
      }

      return info;
   }
}
