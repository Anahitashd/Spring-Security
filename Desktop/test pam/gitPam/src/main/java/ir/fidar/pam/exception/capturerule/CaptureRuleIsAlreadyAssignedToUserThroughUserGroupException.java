package ir.fidar.pam.exception.capturerule;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.Map;

public class CaptureRuleIsAlreadyAssignedToUserThroughUserGroupException extends AbstractException {
   private final String userUsername;
   private final String userGroupName;

   public CaptureRuleIsAlreadyAssignedToUserThroughUserGroupException(String userUsername, String userGroupName) {
      this.userUsername = userUsername;
      this.userGroupName = userGroupName;
   }

   @Override
   public String getCode() {
      return "capture_rule.users.alrdy_access_by_group";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      return this.buildInfo().add("user", this.userUsername).add("group", this.userGroupName);
   }
}
