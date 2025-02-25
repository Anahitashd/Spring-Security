package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.Map;

public class UserGroupUserMembershipViolatingAccessRuleConnectionAccessibilityException extends AbstractException {
   private static final String CODE_FORMAT = "user_group.users.violating_access_rule_%sconnection_unique_accessibility%s";
   private final String connection;
   private final String userUsername;
   private final String userUserGroup;
   private final String userAccessRule;
   private final String userConnectionGroup;
   private final String userGroupAccessRule;
   private final String userGroupConnectionGroup;

   public UserGroupUserMembershipViolatingAccessRuleConnectionAccessibilityException(
      String connection,
      String userUsername,
      String userUserGroup,
      String userAccessRule,
      String userConnectionGroup,
      String userGroupAccessRule,
      String userGroupConnectionGroup
   ) {
      this.connection = connection;
      this.userUsername = userUsername;
      this.userUserGroup = userUserGroup;
      this.userAccessRule = userAccessRule;
      this.userConnectionGroup = userConnectionGroup;
      this.userGroupAccessRule = userGroupAccessRule;
      this.userGroupConnectionGroup = userGroupConnectionGroup;
   }

   @Override
   public String getCode() {
      return String.format(
         "user_group.users.violating_access_rule_%sconnection_unique_accessibility%s",
         this.userConnectionGroup == null ? "" : "grouped_",
         this.userUserGroup == null ? "" : "_through_another_group"
      );
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Map<String, Serializable> info = this.buildInfo()
         .add("connection", this.connection)
         .add("user", this.userUsername)
         .add("user-rule", this.userAccessRule)
         .add("user-group-rule", this.userGroupAccessRule);
      if (this.userUserGroup != null) {
         info.put("user-user-group", this.userUserGroup);
      }

      if (this.userConnectionGroup != null) {
         info.put("user-connection-group", this.userConnectionGroup);
      }

      return info;
   }
}
