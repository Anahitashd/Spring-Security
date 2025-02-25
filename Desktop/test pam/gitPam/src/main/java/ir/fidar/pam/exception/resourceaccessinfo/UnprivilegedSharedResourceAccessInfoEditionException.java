package ir.fidar.pam.exception.resourceaccessinfo;

import ir.fidar.core.exception.api.AbstractException;

public class UnprivilegedSharedResourceAccessInfoEditionException extends AbstractException {
   @Override
   public String getCode() {
      return "rai.shared_edit.unprvlged";
   }
}
