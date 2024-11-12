package ir.fidar.pam.exception.connection;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.Map;

public class ConnectionConnectionGroupAssignmentViolatingAccessRuleConnectionAccessibilityException extends AbstractException {
   private static final String CODE_FORMAT = "con.con_groups.violating_access_rule_%sconnection_unique_accessibility%s";
   private final String user;
   private final String connectionGroupName;
   private final String connectionConnectionGroup;
   private final String connectionAccessRule;
   private final String connectionUserGroup;
   private final String connectionGroupAccessRule;
   private final String connectionGroupUserGroup;

   public ConnectionConnectionGroupAssignmentViolatingAccessRuleConnectionAccessibilityException(
      String user,
      String connectionGroupName,
      String connectionConnectionGroup,
      String connectionAccessRule,
      String connectionUserGroup,
      String connectionGroupAccessRule,
      String connectionGroupUserGroup
   ) {
      this.user = user;
      this.connectionGroupName = connectionGroupName;
      this.connectionConnectionGroup = connectionConnectionGroup;
      this.connectionAccessRule = connectionAccessRule;
      this.connectionUserGroup = connectionUserGroup;
      this.connectionGroupAccessRule = connectionGroupAccessRule;
      this.connectionGroupUserGroup = connectionGroupUserGroup;
   }

   @Override
   public String getCode() {
      return String.format(
         "con.con_groups.violating_access_rule_%sconnection_unique_accessibility%s",
         this.connectionGroupUserGroup == null ? "" : "grouped_",
         this.connectionConnectionGroup == null ? "" : "_through_another_group"
      );
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Map<String, Serializable> info = this.buildInfo()
         .add("user", this.user)
         .add("connection-group", this.connectionGroupName)
         .add("connection-rule", this.connectionAccessRule)
         .add("connection-group-rule", this.connectionGroupAccessRule);
      if (this.connectionConnectionGroup != null) {
         info.put("connection-connection-group", this.connectionConnectionGroup);
      }

      if (this.connectionUserGroup != null) {
         info.put("connection-group-user-group", this.connectionGroupUserGroup);
      }

      return info;
   }
}
