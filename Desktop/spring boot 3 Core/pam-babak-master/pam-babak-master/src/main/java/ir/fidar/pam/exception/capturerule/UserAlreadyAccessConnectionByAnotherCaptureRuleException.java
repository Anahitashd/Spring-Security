package ir.fidar.pam.exception.capturerule;

import ir.fidar.core.exception.api.AbstractException;
import ir.fidar.core.exception.api.Exception;
import ir.fidar.core.util.StringUtils;
import java.io.Serializable;
import java.util.Map;

public class UserAlreadyAccessConnectionByAnotherCaptureRuleException extends AbstractException {
   private final String userUsername;
   private final String captureRuleName;
   private final String connectionName;
   protected final String connectionGroupName;

   public UserAlreadyAccessConnectionByAnotherCaptureRuleException(String userUsername, String captureRuleName, String connectionName) {
      this(userUsername, captureRuleName, connectionName, null);
   }

   public UserAlreadyAccessConnectionByAnotherCaptureRuleException(
      String userUsername, String captureRuleName, String connectionName, String connectionGroupName
   ) {
      this.userUsername = userUsername;
      this.captureRuleName = captureRuleName;
      this.connectionName = connectionName;
      this.connectionGroupName = connectionGroupName;
   }

   @Override
   public String getCode() {
      return StringUtils.hasContent(this.connectionGroupName)
         ? "capture_rule.users.alrdy_access_grouped_con_individually"
         : "capture_rule.users.alrdy_access_con_individually";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      Exception.InfoBuilder info = this.buildInfo().add("capture-rule", this.captureRuleName).add("user", this.userUsername).add("con", this.connectionName);
      if (StringUtils.hasContent(this.connectionGroupName)) {
         info.add("con-group", this.connectionGroupName);
      }

      return info;
   }
}
