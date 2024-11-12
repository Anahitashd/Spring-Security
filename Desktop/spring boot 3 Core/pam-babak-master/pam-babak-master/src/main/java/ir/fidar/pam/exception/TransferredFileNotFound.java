package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;

public class TransferredFileNotFound extends AbstractException {
   @Override
   public String getCode() {
      return "capture.transferred_file.not_found";
   }
}
