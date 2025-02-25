package ir.fidar.pam.exception.connectionaccessrequest;

import ir.fidar.core.exception.api.AbstractException;

public class ConnectionAccessRequestOwnershipException extends AbstractException {
   @Override
   public String getCode() {
      return "con_access_req.not_owner";
   }
}
