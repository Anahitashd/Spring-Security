package ir.fidar.pam.exception.connectionaccessrequest;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.Map;

public class AlreadyHasAccessToRequestedHostException extends AbstractException {
   private final String accessRuleName;

   public AlreadyHasAccessToRequestedHostException(String accessRuleName) {
      this.accessRuleName = accessRuleName;
   }

   @Override
   public String getCode() {
      return "con_access_req.user.alrdy_has_access";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      return this.buildInfo().add("name", this.accessRuleName);
   }
}
