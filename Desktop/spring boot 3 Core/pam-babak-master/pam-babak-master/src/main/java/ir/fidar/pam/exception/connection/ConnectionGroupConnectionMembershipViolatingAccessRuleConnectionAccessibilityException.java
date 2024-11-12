package ir.fidar.pam.exception.connection;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.Map;

public class ConnectionGroupConnectionMembershipViolatingAccessRuleConnectionAccessibilityException extends AbstractException {
   private static final String CODE_FORMAT = "con_group.cons.violating_access_rule_%suser_unique_accessibility%s";
   private final String user;
   private final String connectionName;
   private final String connectionConnectionGroup;
   private final String connectionAccessRule;
   private final String connectionUserGroup;
   private final String connectionGroupAccessRule;
   private final String connectionGroupUserGroup;

   public ConnectionGroupConnectionMembershipViolatingAccessRuleConnectionAccessibilityException(
      String user,
      String connectionName,
      String connectionConnectionGroup,
      String connectionAccessRule,
      String connectionUserGroup,
      String connectionGroupAccessRule,
      String connectionGroupUserGroup
   ) {
      this.user = user;
      this.connectionName = connectionName;
      this.connectionConnectionGroup = connectionConnectionGroup;
      this.connectionAccessRule = connectionAccessRule;
      this.connectionUserGroup = connectionUserGroup;
      this.connectionGroupAccessRule = connectionGroupAccessRule;
      this.connectionGroupUserGroup = connectionGroupUserGroup;
   }

   @Override
   public String getCode() {
      return String.format(
         "con_group.cons.violating_access_rule_%suser_unique_accessibility%s",
         this.connectionUserGroup == null ? "" : "grouped_",
         this.connectionConnectionGroup == null ? "" : "_through_another_group"
      );
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Map<String, Serializable> info = this.buildInfo()
         .add("user", this.user)
         .add("connection", this.connectionName)
         .add("connection-rule", this.connectionAccessRule)
         .add("connection-group-rule", this.connectionGroupAccessRule);
      if (this.connectionConnectionGroup != null) {
         info.put("connection-connection-group", this.connectionConnectionGroup);
      }

      if (this.connectionUserGroup != null) {
         info.put("connection-user-group", this.connectionUserGroup);
      }

      return info;
   }
}
