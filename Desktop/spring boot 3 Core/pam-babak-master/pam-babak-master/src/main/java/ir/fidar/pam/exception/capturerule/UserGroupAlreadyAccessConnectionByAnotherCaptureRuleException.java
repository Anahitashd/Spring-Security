package ir.fidar.pam.exception.capturerule;

import ir.fidar.core.exception.api.AbstractException;
import ir.fidar.core.exception.api.Exception;
import ir.fidar.core.util.StringUtils;
import java.io.Serializable;
import java.util.Map;

public class UserGroupAlreadyAccessConnectionByAnotherCaptureRuleException extends AbstractException {
   private final String groupName;
   private final String captureRuleName;
   private final String connectionName;
   private final String connectionGroupName;

   public UserGroupAlreadyAccessConnectionByAnotherCaptureRuleException(String groupName, String captureRuleName, String connectionName) {
      this(groupName, captureRuleName, connectionName, null);
   }

   public UserGroupAlreadyAccessConnectionByAnotherCaptureRuleException(
      String groupName, String captureRuleName, String connectionName, String connectionGroupName
   ) {
      this.groupName = groupName;
      this.captureRuleName = captureRuleName;
      this.connectionName = connectionName;
      this.connectionGroupName = connectionGroupName;
   }

   @Override
   public String getCode() {
      return StringUtils.hasContent(this.connectionGroupName)
         ? "capture_rule.user_groups.alrdy_access_grouped_con"
         : "capture_rule.user_groups.alrdy_access_con";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Exception.InfoBuilder info = this.buildInfo().add("capture-rule", this.captureRuleName).add("group", this.groupName).add("con", this.connectionName);
      if (StringUtils.hasContent(this.connectionGroupName)) {
         info.add("con-group", this.connectionGroupName);
      }

      return info;
   }
}
