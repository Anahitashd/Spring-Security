package ir.fidar.pam.domain.util.converter.attribbute;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.SessionTransferFileMode;

public class SessionTransferredFileModeConverter extends GenericEnumAttributeConverter<SessionTransferFileMode> {
   public SessionTransferredFileModeConverter() {
      this.enumClass = SessionTransferFileMode.class;
   }
}
