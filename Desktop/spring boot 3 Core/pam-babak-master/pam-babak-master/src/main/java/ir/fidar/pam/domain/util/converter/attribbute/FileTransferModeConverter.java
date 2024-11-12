package ir.fidar.pam.domain.util.converter.attribbute;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.FileTransferMode;

public class FileTransferModeConverter extends GenericEnumAttributeConverter<FileTransferMode> {
   public FileTransferModeConverter() {
      this.enumClass = FileTransferMode.class;
   }
}
