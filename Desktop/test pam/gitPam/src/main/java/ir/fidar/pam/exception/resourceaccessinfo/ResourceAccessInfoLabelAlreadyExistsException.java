package ir.fidar.pam.exception.resourceaccessinfo;

import ir.fidar.core.exception.api.AbstractException;

public class ResourceAccessInfoLabelAlreadyExistsException extends AbstractException {
   @Override
   public String getCode() {
      return "rai.lbl.dup";
   }
}
