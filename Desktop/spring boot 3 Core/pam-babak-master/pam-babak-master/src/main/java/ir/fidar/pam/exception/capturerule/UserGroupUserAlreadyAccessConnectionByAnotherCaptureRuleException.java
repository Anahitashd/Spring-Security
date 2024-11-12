package ir.fidar.pam.exception.capturerule;

import ir.fidar.core.exception.api.Exception;
import ir.fidar.core.util.StringUtils;
import java.io.Serializable;
import java.util.Map;

public class UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleException extends UserAlreadyAccessConnectionByAnotherCaptureRuleException {
   private final String currentUserGroupName;

   public UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleException(
      String userUsername, String captureRuleName, String connectionName, String currentUserGroupName
   ) {
      super(userUsername, captureRuleName, connectionName);
      this.currentUserGroupName = currentUserGroupName;
   }

   public UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleException(
      String userUsername, String captureRuleName, String connectionName, String connectionGroupName, String currentUserGroupName
   ) {
      super(userUsername, captureRuleName, connectionName, connectionGroupName);
      this.currentUserGroupName = currentUserGroupName;
   }

   @Override
   public String getCode() {
      return StringUtils.hasContent(this.connectionGroupName)
         ? "capture_rule.user_groups.user_alrdy_access_grouped_con_individually"
         : "capture_rule.user_groups.user_alrdy_access_con_individually";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Exception.InfoBuilder info = (Exception.InfoBuilder)super.getInfo();
      info.add("curr-group", this.currentUserGroupName);
      return info;
   }
}
