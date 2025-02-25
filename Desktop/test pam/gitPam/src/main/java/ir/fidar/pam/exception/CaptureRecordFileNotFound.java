package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;

public class CaptureRecordFileNotFound extends AbstractException {
   @Override
   public String getCode() {
      return "capture.record_not_found";
   }
}
