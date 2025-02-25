package ir.fidar.pam.domain.util.converter.attribbute;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.SessionTransferredFileStatus;

public class SessionTransferredFileStatusConverter extends GenericEnumAttributeConverter<SessionTransferredFileStatus> {
   public SessionTransferredFileStatusConverter() {
      this.enumClass = SessionTransferredFileStatus.class;
   }
}
