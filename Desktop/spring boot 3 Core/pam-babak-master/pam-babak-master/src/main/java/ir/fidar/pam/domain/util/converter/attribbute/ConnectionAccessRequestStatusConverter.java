package ir.fidar.pam.domain.util.converter.attribbute;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.ConnectionAccessRequestStatus;

public class ConnectionAccessRequestStatusConverter extends GenericEnumAttributeConverter<ConnectionAccessRequestStatus> {
   public ConnectionAccessRequestStatusConverter() {
      this.enumClass = ConnectionAccessRequestStatus.class;
   }
}
