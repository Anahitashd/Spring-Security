package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;

public class CaptureExecutedCommandNotSupportedException extends AbstractException {
   @Override
   public String getCode() {
      return "capture.exec_cmd.not_supported";
   }
}
