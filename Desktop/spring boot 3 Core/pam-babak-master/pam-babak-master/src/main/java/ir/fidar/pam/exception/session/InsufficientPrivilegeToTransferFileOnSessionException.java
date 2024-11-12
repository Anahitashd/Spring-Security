package ir.fidar.pam.exception.session;

import ir.fidar.core.exception.api.AbstractException;

public class InsufficientPrivilegeToTransferFileOnSessionException extends AbstractException {
   @Override
   public String getCode() {
      return "session.intercept-stream.insuffcnt_prvlg";
   }
}
