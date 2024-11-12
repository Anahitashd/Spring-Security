package ir.fidar.pam.exception.capturerule;

import ir.fidar.core.exception.api.Exception;
import ir.fidar.core.util.StringUtils;
import java.io.Serializable;
import java.util.Map;

public class UserAlreadyAccessConnectionByAnotherCaptureRuleThroughUserGroupException extends UserAlreadyAccessConnectionByAnotherCaptureRuleException {
   private final String userGroupName;

   public UserAlreadyAccessConnectionByAnotherCaptureRuleThroughUserGroupException(
      String userUsername, String captureRuleName, String connectionName, String userGroupName
   ) {
      super(userUsername, captureRuleName, connectionName);
      this.userGroupName = userGroupName;
   }

   public UserAlreadyAccessConnectionByAnotherCaptureRuleThroughUserGroupException(
      String userUsername, String captureRuleName, String connectionName, String connectionGroupName, String userGroupName
   ) {
      super(userUsername, captureRuleName, connectionName, connectionGroupName);
      this.userGroupName = userGroupName;
   }

   @Override
   public String getCode() {
      return StringUtils.hasContent(this.connectionGroupName)
         ? "capture_rule.users.alrdy_access_grouped_con_by_group"
         : "capture_rule.users.alrdy_access_con_by_group";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Exception.InfoBuilder info = (Exception.InfoBuilder)super.getInfo();
      info.add("group", this.userGroupName);
      return info;
   }
}
