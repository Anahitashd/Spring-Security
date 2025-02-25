package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;

public class InvalidImportExcelFileFormatException extends AbstractException {
   @Override
   public String getCode() {
      return "ie.file.invalid_format";
   }
}
