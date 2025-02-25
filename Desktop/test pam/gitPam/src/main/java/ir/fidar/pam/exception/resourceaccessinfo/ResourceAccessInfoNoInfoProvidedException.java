package ir.fidar.pam.exception.resourceaccessinfo;

import ir.fidar.core.exception.api.AbstractException;

public class ResourceAccessInfoNoInfoProvidedException extends AbstractException {
   @Override
   public String getCode() {
      return "rai.info_not_provided";
   }
}
