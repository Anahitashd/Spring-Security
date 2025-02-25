package ir.fidar.pam.exception.session;

import ir.fidar.core.exception.api.AbstractException;

public class InsufficientPrivilegeToAccessSessionException extends AbstractException {
   @Override
   public String getCode() {
      return "session.insuffcnt_prvlg";
   }

   @Override
   public int getMappedHttpCode() {
      return 403;
   }
}
