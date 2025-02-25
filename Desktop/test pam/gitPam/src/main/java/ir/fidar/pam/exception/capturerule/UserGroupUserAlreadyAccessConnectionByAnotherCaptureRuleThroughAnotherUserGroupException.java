package ir.fidar.pam.exception.capturerule;

import ir.fidar.core.exception.api.Exception;
import ir.fidar.core.util.StringUtils;
import java.io.Serializable;
import java.util.Map;

public class UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleThroughAnotherUserGroupException
   extends UserAlreadyAccessConnectionByAnotherCaptureRuleThroughUserGroupException {
   private final String currentUserGroupName;

   public UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleThroughAnotherUserGroupException(
      String userUsername, String captureRuleName, String connectionName, String userGroupName, String currentUserGroupName
   ) {
      super(userUsername, captureRuleName, connectionName, userGroupName);
      this.currentUserGroupName = currentUserGroupName;
   }

   public UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleThroughAnotherUserGroupException(
      String userUsername, String captureRuleName, String connectionName, String connectionGroupName, String userGroupName, String currentUserGroupName
   ) {
      super(userUsername, captureRuleName, connectionName, connectionGroupName, userGroupName);
      this.currentUserGroupName = currentUserGroupName;
   }

   @Override
   public String getCode() {
      return StringUtils.hasContent(this.connectionGroupName)
         ? "capture_rule.user_groups.user_alrdy_access_grouped_con_by_group"
         : "capture_rule.user_groups.user_alrdy_access_con_by_group";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Exception.InfoBuilder info = (Exception.InfoBuilder)super.getInfo();
      info.add("curr-group", this.currentUserGroupName);
      return info;
   }
}
