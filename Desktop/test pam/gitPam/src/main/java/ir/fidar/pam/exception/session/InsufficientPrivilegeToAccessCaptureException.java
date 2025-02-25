package ir.fidar.pam.exception.session;

import ir.fidar.core.exception.api.AbstractException;

public class InsufficientPrivilegeToAccessCaptureException extends AbstractException {
   @Override
   public String getCode() {
      return "capture.insuffcnt_prvlg";
   }

   @Override
   public int getMappedHttpCode() {
      return 403;
   }
}
