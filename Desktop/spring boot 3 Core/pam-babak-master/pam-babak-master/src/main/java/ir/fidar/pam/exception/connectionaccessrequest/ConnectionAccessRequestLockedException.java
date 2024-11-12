package ir.fidar.pam.exception.connectionaccessrequest;

import ir.fidar.core.exception.api.AbstractException;

public class ConnectionAccessRequestLockedException extends AbstractException {
   @Override
   public String getCode() {
      return "con_access_req.upd.locked";
   }
}
